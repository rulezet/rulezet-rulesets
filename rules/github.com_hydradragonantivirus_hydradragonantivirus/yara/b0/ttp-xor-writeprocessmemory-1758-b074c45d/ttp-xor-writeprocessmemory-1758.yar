rule TTP_XOR_WriteProcessMemory_1758 {
  strings:
    $key_1758 = { 40 2a [2] 72 08 [2] 74 3d [2] 5a 3d [2] 65 21 }

  condition:
    any of them
}