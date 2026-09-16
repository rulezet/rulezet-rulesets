rule TTP_XOR_WriteProcessMemory_7b93 {
  strings:
    $key_7b93 = { 2c e1 [2] 1e c3 [2] 18 f6 [2] 36 f6 [2] 09 ea }

  condition:
    any of them
}