rule TTP_XOR_WriteProcessMemory_2087 {
  strings:
    $key_2087 = { 77 f5 [2] 45 d7 [2] 43 e2 [2] 6d e2 [2] 52 fe }

  condition:
    any of them
}