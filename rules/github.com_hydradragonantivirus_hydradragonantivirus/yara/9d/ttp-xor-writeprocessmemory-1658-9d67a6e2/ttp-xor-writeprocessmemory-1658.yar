rule TTP_XOR_WriteProcessMemory_1658 {
  strings:
    $key_1658 = { 41 2a [2] 73 08 [2] 75 3d [2] 5b 3d [2] 64 21 }

  condition:
    any of them
}