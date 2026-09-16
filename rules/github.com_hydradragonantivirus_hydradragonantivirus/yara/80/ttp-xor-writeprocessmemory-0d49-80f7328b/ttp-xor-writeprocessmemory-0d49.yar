rule TTP_XOR_WriteProcessMemory_0d49 {
  strings:
    $key_0d49 = { 5a 3b [2] 68 19 [2] 6e 2c [2] 40 2c [2] 7f 30 }

  condition:
    any of them
}