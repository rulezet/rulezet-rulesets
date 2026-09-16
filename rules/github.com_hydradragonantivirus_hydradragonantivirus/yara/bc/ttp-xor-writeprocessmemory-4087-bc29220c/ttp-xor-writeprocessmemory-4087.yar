rule TTP_XOR_WriteProcessMemory_4087 {
  strings:
    $key_4087 = { 17 f5 [2] 25 d7 [2] 23 e2 [2] 0d e2 [2] 32 fe }

  condition:
    any of them
}