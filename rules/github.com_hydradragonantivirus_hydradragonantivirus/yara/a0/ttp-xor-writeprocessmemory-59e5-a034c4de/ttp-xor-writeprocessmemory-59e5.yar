rule TTP_XOR_WriteProcessMemory_59e5 {
  strings:
    $key_59e5 = { 0e 97 [2] 3c b5 [2] 3a 80 [2] 14 80 [2] 2b 9c }

  condition:
    any of them
}