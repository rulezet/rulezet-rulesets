rule TTP_XOR_WriteProcessMemory_0869 {
  strings:
    $key_0869 = { 5f 1b [2] 6d 39 [2] 6b 0c [2] 45 0c [2] 7a 10 }

  condition:
    any of them
}