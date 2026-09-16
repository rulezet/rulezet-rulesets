rule TTP_XOR_WriteProcessMemory_3d93 {
  strings:
    $key_3d93 = { 6a e1 [2] 58 c3 [2] 5e f6 [2] 70 f6 [2] 4f ea }

  condition:
    any of them
}