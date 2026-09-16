rule TTP_XOR_WriteProcessMemory_3e44 {
  strings:
    $key_3e44 = { 69 36 [2] 5b 14 [2] 5d 21 [2] 73 21 [2] 4c 3d }

  condition:
    any of them
}