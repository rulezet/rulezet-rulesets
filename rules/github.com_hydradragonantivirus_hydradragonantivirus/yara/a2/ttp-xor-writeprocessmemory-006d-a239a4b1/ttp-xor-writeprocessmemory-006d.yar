rule TTP_XOR_WriteProcessMemory_006d {
  strings:
    $key_006d = { 57 1f [2] 65 3d [2] 63 08 [2] 4d 08 [2] 72 14 }

  condition:
    any of them
}