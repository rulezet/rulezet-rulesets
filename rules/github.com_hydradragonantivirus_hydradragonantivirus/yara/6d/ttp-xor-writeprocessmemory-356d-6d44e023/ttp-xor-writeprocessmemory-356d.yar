rule TTP_XOR_WriteProcessMemory_356d {
  strings:
    $key_356d = { 62 1f [2] 50 3d [2] 56 08 [2] 78 08 [2] 47 14 }

  condition:
    any of them
}