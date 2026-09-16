rule TTP_XOR_WriteProcessMemory_613d {
  strings:
    $key_613d = { 36 4f [2] 04 6d [2] 02 58 [2] 2c 58 [2] 13 44 }

  condition:
    any of them
}