rule TTP_XOR_WriteProcessMemory_5c44 {
  strings:
    $key_5c44 = { 0b 36 [2] 39 14 [2] 3f 21 [2] 11 21 [2] 2e 3d }

  condition:
    any of them
}