rule TTP_XOR_WriteProcessMemory_1839 {
  strings:
    $key_1839 = { 4f 4b [2] 7d 69 [2] 7b 5c [2] 55 5c [2] 6a 40 }

  condition:
    any of them
}