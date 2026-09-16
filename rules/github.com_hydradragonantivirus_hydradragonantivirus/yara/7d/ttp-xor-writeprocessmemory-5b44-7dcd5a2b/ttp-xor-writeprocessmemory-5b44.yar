rule TTP_XOR_WriteProcessMemory_5b44 {
  strings:
    $key_5b44 = { 0c 36 [2] 3e 14 [2] 38 21 [2] 16 21 [2] 29 3d }

  condition:
    any of them
}