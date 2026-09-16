rule TTP_XOR_WriteProcessMemory_f244 {
  strings:
    $key_f244 = { a5 36 [2] 97 14 [2] 91 21 [2] bf 21 [2] 80 3d }

  condition:
    any of them
}