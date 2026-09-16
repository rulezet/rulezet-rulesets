rule TTP_XOR_WriteProcessMemory_454d {
  strings:
    $key_454d = { 12 3f [2] 20 1d [2] 26 28 [2] 08 28 [2] 37 34 }

  condition:
    any of them
}