rule TTP_XOR_WriteProcessMemory_4144 {
  strings:
    $key_4144 = { 16 36 [2] 24 14 [2] 22 21 [2] 0c 21 [2] 33 3d }

  condition:
    any of them
}