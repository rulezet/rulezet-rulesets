rule TTP_XOR_WriteProcessMemory_076d {
  strings:
    $key_076d = { 50 1f [2] 62 3d [2] 64 08 [2] 4a 08 [2] 75 14 }

  condition:
    any of them
}