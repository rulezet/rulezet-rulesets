rule TTP_XOR_WriteProcessMemory_a3b8 {
  strings:
    $key_a3b8 = { f4 ca [2] c6 e8 [2] c0 dd [2] ee dd [2] d1 c1 }

  condition:
    any of them
}