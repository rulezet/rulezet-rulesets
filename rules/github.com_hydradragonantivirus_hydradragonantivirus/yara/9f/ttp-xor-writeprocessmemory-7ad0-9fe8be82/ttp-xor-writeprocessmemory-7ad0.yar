rule TTP_XOR_WriteProcessMemory_7ad0 {
  strings:
    $key_7ad0 = { 2d a2 [2] 1f 80 [2] 19 b5 [2] 37 b5 [2] 08 a9 }

  condition:
    any of them
}