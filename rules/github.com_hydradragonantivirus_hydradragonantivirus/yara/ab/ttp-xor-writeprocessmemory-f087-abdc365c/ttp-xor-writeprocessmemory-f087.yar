rule TTP_XOR_WriteProcessMemory_f087 {
  strings:
    $key_f087 = { a7 f5 [2] 95 d7 [2] 93 e2 [2] bd e2 [2] 82 fe }

  condition:
    any of them
}