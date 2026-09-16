rule TTP_XOR_WriteProcessMemory_5d44 {
  strings:
    $key_5d44 = { 0a 36 [2] 38 14 [2] 3e 21 [2] 10 21 [2] 2f 3d }

  condition:
    any of them
}