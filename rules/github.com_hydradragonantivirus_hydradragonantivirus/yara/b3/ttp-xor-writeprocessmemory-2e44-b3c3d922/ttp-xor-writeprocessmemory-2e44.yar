rule TTP_XOR_WriteProcessMemory_2e44 {
  strings:
    $key_2e44 = { 79 36 [2] 4b 14 [2] 4d 21 [2] 63 21 [2] 5c 3d }

  condition:
    any of them
}