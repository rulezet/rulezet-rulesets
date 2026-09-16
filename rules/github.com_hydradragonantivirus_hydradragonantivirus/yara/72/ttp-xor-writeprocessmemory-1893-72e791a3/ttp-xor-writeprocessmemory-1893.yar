rule TTP_XOR_WriteProcessMemory_1893 {
  strings:
    $key_1893 = { 4f e1 [2] 7d c3 [2] 7b f6 [2] 55 f6 [2] 6a ea }

  condition:
    any of them
}