rule TTP_XOR_WriteProcessMemory_d087 {
  strings:
    $key_d087 = { 87 f5 [2] b5 d7 [2] b3 e2 [2] 9d e2 [2] a2 fe }

  condition:
    any of them
}