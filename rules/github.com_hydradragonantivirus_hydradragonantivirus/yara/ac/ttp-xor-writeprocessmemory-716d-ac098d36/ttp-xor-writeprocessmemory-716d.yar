rule TTP_XOR_WriteProcessMemory_716d {
  strings:
    $key_716d = { 26 1f [2] 14 3d [2] 12 08 [2] 3c 08 [2] 03 14 }

  condition:
    any of them
}