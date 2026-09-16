rule TTP_XOR_WriteProcessMemory_59e9 {
  strings:
    $key_59e9 = { 0e 9b [2] 3c b9 [2] 3a 8c [2] 14 8c [2] 2b 90 }

  condition:
    any of them
}