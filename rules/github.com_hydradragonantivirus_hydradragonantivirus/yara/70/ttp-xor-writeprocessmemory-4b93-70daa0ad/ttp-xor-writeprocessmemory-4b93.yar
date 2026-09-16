rule TTP_XOR_WriteProcessMemory_4b93 {
  strings:
    $key_4b93 = { 1c e1 [2] 2e c3 [2] 28 f6 [2] 06 f6 [2] 39 ea }

  condition:
    any of them
}