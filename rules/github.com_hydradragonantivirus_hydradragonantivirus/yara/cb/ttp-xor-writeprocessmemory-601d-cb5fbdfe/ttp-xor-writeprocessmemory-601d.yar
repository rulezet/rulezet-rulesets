rule TTP_XOR_WriteProcessMemory_601d {
  strings:
    $key_601d = { 37 6f [2] 05 4d [2] 03 78 [2] 2d 78 [2] 12 64 }

  condition:
    any of them
}