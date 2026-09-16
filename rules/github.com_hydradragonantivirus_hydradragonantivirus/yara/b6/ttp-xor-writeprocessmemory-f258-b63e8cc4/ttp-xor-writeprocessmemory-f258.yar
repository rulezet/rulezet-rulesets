rule TTP_XOR_WriteProcessMemory_f258 {
  strings:
    $key_f258 = { a5 2a [2] 97 08 [2] 91 3d [2] bf 3d [2] 80 21 }

  condition:
    any of them
}