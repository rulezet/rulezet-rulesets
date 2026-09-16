rule TTP_XOR_WriteProcessMemory_3918 {
  strings:
    $key_3918 = { 6e 6a [2] 5c 48 [2] 5a 7d [2] 74 7d [2] 4b 61 }

  condition:
    any of them
}