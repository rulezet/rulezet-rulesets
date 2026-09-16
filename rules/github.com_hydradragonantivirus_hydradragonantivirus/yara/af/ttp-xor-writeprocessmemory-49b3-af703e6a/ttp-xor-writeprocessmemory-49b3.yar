rule TTP_XOR_WriteProcessMemory_49b3 {
  strings:
    $key_49b3 = { 1e c1 [2] 2c e3 [2] 2a d6 [2] 04 d6 [2] 3b ca }

  condition:
    any of them
}