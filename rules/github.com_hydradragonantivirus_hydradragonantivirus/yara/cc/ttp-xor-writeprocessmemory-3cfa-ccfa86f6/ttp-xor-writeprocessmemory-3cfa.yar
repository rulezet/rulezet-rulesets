rule TTP_XOR_WriteProcessMemory_3cfa {
  strings:
    $key_3cfa = { 6b 88 [2] 59 aa [2] 5f 9f [2] 71 9f [2] 4e 83 }

  condition:
    any of them
}