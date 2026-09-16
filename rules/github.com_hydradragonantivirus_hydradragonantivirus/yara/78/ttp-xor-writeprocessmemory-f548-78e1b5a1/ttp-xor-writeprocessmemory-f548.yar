rule TTP_XOR_WriteProcessMemory_f548 {
  strings:
    $key_f548 = { a2 3a [2] 90 18 [2] 96 2d [2] b8 2d [2] 87 31 }

  condition:
    any of them
}