rule TTP_XOR_WriteProcessMemory_f558 {
  strings:
    $key_f558 = { a2 2a [2] 90 08 [2] 96 3d [2] b8 3d [2] 87 21 }

  condition:
    any of them
}