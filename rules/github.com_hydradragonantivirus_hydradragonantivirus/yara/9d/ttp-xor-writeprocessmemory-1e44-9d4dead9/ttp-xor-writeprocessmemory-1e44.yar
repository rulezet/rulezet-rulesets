rule TTP_XOR_WriteProcessMemory_1e44 {
  strings:
    $key_1e44 = { 49 36 [2] 7b 14 [2] 7d 21 [2] 53 21 [2] 6c 3d }

  condition:
    any of them
}