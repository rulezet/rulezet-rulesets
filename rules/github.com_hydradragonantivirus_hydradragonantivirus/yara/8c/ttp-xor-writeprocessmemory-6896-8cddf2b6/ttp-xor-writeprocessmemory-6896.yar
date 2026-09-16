rule TTP_XOR_WriteProcessMemory_6896 {
  strings:
    $key_6896 = { 3f e4 [2] 0d c6 [2] 0b f3 [2] 25 f3 [2] 1a ef }

  condition:
    any of them
}