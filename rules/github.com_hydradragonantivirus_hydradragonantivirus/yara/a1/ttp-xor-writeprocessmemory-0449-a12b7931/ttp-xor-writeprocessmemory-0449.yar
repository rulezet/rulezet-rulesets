rule TTP_XOR_WriteProcessMemory_0449 {
  strings:
    $key_0449 = { 53 3b [2] 61 19 [2] 67 2c [2] 49 2c [2] 76 30 }

  condition:
    any of them
}