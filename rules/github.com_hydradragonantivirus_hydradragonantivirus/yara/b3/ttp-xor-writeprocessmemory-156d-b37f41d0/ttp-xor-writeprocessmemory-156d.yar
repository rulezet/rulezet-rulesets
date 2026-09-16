rule TTP_XOR_WriteProcessMemory_156d {
  strings:
    $key_156d = { 42 1f [2] 70 3d [2] 76 08 [2] 58 08 [2] 67 14 }

  condition:
    any of them
}