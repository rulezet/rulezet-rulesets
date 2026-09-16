rule TTP_XOR_WriteProcessMemory_0f69 {
  strings:
    $key_0f69 = { 58 1b [2] 6a 39 [2] 6c 0c [2] 42 0c [2] 7d 10 }

  condition:
    any of them
}