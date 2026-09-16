rule TTP_XOR_WriteProcessMemory_2cf9 {
  strings:
    $key_2cf9 = { 7b 8b [2] 49 a9 [2] 4f 9c [2] 61 9c [2] 5e 80 }

  condition:
    any of them
}