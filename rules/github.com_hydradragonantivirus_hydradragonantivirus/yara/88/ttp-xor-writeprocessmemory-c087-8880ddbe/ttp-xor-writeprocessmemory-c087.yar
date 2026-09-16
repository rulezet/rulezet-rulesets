rule TTP_XOR_WriteProcessMemory_c087 {
  strings:
    $key_c087 = { 97 f5 [2] a5 d7 [2] a3 e2 [2] 8d e2 [2] b2 fe }

  condition:
    any of them
}