rule TTP_XOR_WriteProcessMemory_4893 {
  strings:
    $key_4893 = { 1f e1 [2] 2d c3 [2] 2b f6 [2] 05 f6 [2] 3a ea }

  condition:
    any of them
}