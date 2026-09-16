rule TTP_XOR_WriteProcessMemory_1b93 {
  strings:
    $key_1b93 = { 4c e1 [2] 7e c3 [2] 78 f6 [2] 56 f6 [2] 69 ea }

  condition:
    any of them
}