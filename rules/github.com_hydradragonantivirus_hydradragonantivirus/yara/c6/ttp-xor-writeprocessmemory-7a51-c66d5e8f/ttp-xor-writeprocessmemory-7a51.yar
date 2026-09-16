rule TTP_XOR_WriteProcessMemory_7a51 {
  strings:
    $key_7a51 = { 2d 23 [2] 1f 01 [2] 19 34 [2] 37 34 [2] 08 28 }

  condition:
    any of them
}