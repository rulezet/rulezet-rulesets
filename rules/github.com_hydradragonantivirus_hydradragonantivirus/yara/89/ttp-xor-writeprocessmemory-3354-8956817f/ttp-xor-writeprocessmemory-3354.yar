rule TTP_XOR_WriteProcessMemory_3354 {
  strings:
    $key_3354 = { 64 26 [2] 56 04 [2] 50 31 [2] 7e 31 [2] 41 2d }

  condition:
    any of them
}