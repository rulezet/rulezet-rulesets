rule TTP_XOR_WriteProcessMemory_4896 {
  strings:
    $key_4896 = { 1f e4 [2] 2d c6 [2] 2b f3 [2] 05 f3 [2] 3a ef }

  condition:
    any of them
}