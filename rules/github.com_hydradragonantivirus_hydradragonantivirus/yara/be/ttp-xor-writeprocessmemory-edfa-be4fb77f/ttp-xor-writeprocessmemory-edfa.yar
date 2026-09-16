rule TTP_XOR_WriteProcessMemory_edfa {
  strings:
    $key_edfa = { ba 88 [2] 88 aa [2] 8e 9f [2] a0 9f [2] 9f 83 }

  condition:
    any of them
}