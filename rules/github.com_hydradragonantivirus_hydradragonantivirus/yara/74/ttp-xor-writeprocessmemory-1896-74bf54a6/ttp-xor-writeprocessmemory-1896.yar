rule TTP_XOR_WriteProcessMemory_1896 {
  strings:
    $key_1896 = { 4f e4 [2] 7d c6 [2] 7b f3 [2] 55 f3 [2] 6a ef }

  condition:
    any of them
}