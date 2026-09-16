rule TTP_XOR_WriteProcessMemory_7087 {
  strings:
    $key_7087 = { 27 f5 [2] 15 d7 [2] 13 e2 [2] 3d e2 [2] 02 fe }

  condition:
    any of them
}