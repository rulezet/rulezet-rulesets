rule TTP_XOR_WriteProcessMemory_7a65 {
  strings:
    $key_7a65 = { 2d 17 [2] 1f 35 [2] 19 00 [2] 37 00 [2] 08 1c }

  condition:
    any of them
}