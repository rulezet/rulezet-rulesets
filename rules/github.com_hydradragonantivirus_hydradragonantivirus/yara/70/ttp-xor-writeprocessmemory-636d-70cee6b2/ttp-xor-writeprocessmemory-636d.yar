rule TTP_XOR_WriteProcessMemory_636d {
  strings:
    $key_636d = { 34 1f [2] 06 3d [2] 00 08 [2] 2e 08 [2] 11 14 }

  condition:
    any of them
}