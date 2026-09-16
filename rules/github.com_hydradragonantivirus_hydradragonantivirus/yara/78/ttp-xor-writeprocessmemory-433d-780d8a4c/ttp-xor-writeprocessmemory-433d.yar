rule TTP_XOR_WriteProcessMemory_433d {
  strings:
    $key_433d = { 14 4f [2] 26 6d [2] 20 58 [2] 0e 58 [2] 31 44 }

  condition:
    any of them
}