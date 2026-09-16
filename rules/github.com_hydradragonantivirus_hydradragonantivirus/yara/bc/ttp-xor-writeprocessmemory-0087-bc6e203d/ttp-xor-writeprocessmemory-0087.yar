rule TTP_XOR_WriteProcessMemory_0087 {
  strings:
    $key_0087 = { 57 f5 [2] 65 d7 [2] 63 e2 [2] 4d e2 [2] 72 fe }

  condition:
    any of them
}