rule TTP_XOR_WriteProcessMemory_eded {
  strings:
    $key_eded = { ba 9f [2] 88 bd [2] 8e 88 [2] a0 88 [2] 9f 94 }

  condition:
    any of them
}