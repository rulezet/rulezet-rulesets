rule TTP_XOR_WriteProcessMemory_0a44 {
  strings:
    $key_0a44 = { 5d 36 [2] 6f 14 [2] 69 21 [2] 47 21 [2] 78 3d }

  condition:
    any of them
}