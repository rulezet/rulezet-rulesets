rule TTP_XOR_WriteProcessMemory_6b93 {
  strings:
    $key_6b93 = { 3c e1 [2] 0e c3 [2] 08 f6 [2] 26 f6 [2] 19 ea }

  condition:
    any of them
}