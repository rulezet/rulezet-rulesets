rule TTP_XOR_WriteProcessMemory_4e82 {
  strings:
    $key_4e82 = { 19 f0 [2] 2b d2 [2] 2d e7 [2] 03 e7 [2] 3c fb }

  condition:
    any of them
}