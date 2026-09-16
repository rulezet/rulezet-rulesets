rule TTP_XOR_WriteProcessMemory_56d9 {
  strings:
    $key_56d9 = { 01 ab [2] 33 89 [2] 35 bc [2] 1b bc [2] 24 a0 }

  condition:
    any of them
}