rule TTP_XOR_WriteProcessMemory_1c44 {
  strings:
    $key_1c44 = { 4b 36 [2] 79 14 [2] 7f 21 [2] 51 21 [2] 6e 3d }

  condition:
    any of them
}