rule TTP_XOR_WriteProcessMemory_3c44 {
  strings:
    $key_3c44 = { 6b 36 [2] 59 14 [2] 5f 21 [2] 71 21 [2] 4e 3d }

  condition:
    any of them
}