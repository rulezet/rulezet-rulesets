rule TTP_XOR_WriteProcessMemory_dc84 {
  strings:
    $key_dc84 = { 8b f6 [2] b9 d4 [2] bf e1 [2] 91 e1 [2] ae fd }

  condition:
    any of them
}