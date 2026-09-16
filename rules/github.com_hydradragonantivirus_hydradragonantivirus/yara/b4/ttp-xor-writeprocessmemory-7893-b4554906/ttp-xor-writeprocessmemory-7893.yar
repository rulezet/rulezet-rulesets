rule TTP_XOR_WriteProcessMemory_7893 {
  strings:
    $key_7893 = { 2f e1 [2] 1d c3 [2] 1b f6 [2] 35 f6 [2] 0a ea }

  condition:
    any of them
}