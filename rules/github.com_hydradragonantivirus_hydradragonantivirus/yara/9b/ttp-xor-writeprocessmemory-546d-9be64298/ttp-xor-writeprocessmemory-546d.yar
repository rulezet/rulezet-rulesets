rule TTP_XOR_WriteProcessMemory_546d {
  strings:
    $key_546d = { 03 1f [2] 31 3d [2] 37 08 [2] 19 08 [2] 26 14 }

  condition:
    any of them
}