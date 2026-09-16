rule TTP_XOR_WriteProcessMemory_ce3d {
  strings:
    $key_ce3d = { 99 4f [2] ab 6d [2] ad 58 [2] 83 58 [2] bc 44 }

  condition:
    any of them
}