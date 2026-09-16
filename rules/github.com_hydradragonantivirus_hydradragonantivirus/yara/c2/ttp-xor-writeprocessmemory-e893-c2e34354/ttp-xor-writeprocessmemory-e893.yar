rule TTP_XOR_WriteProcessMemory_e893 {
  strings:
    $key_e893 = { bf e1 [2] 8d c3 [2] 8b f6 [2] a5 f6 [2] 9a ea }

  condition:
    any of them
}