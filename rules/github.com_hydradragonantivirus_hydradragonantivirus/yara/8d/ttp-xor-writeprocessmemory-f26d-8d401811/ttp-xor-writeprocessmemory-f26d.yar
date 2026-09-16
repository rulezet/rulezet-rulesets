rule TTP_XOR_WriteProcessMemory_f26d {
  strings:
    $key_f26d = { a5 1f [2] 97 3d [2] 91 08 [2] bf 08 [2] 80 14 }

  condition:
    any of them
}