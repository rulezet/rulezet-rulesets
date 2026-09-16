rule TTP_XOR_WriteProcessMemory_4069 {
  strings:
    $key_4069 = { 17 1b [2] 25 39 [2] 23 0c [2] 0d 0c [2] 32 10 }

  condition:
    any of them
}