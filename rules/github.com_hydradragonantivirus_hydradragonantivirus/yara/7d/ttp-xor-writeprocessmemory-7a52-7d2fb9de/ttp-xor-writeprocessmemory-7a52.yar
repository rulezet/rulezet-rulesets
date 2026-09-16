rule TTP_XOR_WriteProcessMemory_7a52 {
  strings:
    $key_7a52 = { 2d 20 [2] 1f 02 [2] 19 37 [2] 37 37 [2] 08 2b }

  condition:
    any of them
}