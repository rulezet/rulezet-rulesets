rule TTP_XOR_WriteProcessMemory_456d {
  strings:
    $key_456d = { 12 1f [2] 20 3d [2] 26 08 [2] 08 08 [2] 37 14 }

  condition:
    any of them
}