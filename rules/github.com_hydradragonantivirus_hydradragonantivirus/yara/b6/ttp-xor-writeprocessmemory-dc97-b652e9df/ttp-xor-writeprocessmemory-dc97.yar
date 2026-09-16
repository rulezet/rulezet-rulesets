rule TTP_XOR_WriteProcessMemory_dc97 {
  strings:
    $key_dc97 = { 8b e5 [2] b9 c7 [2] bf f2 [2] 91 f2 [2] ae ee }

  condition:
    any of them
}