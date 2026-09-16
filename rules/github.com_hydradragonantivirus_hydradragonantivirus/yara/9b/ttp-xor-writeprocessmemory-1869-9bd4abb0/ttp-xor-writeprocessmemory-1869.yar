rule TTP_XOR_WriteProcessMemory_1869 {
  strings:
    $key_1869 = { 4f 1b [2] 7d 39 [2] 7b 0c [2] 55 0c [2] 6a 10 }

  condition:
    any of them
}