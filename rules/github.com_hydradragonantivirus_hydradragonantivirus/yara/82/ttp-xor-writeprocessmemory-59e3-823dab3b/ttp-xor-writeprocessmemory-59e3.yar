rule TTP_XOR_WriteProcessMemory_59e3 {
  strings:
    $key_59e3 = { 0e 91 [2] 3c b3 [2] 3a 86 [2] 14 86 [2] 2b 9a }

  condition:
    any of them
}