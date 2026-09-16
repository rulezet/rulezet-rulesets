rule TTP_XOR_WriteProcessMemory_4894 {
  strings:
    $key_4894 = { 1f e6 [2] 2d c4 [2] 2b f1 [2] 05 f1 [2] 3a ed }

  condition:
    any of them
}