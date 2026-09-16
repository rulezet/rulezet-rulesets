rule TTP_XOR_WriteProcessMemory_6b44 {
  strings:
    $key_6b44 = { 3c 36 [2] 0e 14 [2] 08 21 [2] 26 21 [2] 19 3d }

  condition:
    any of them
}