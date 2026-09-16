rule TTP_XOR_WriteProcessMemory_614d {
  strings:
    $key_614d = { 36 3f [2] 04 1d [2] 02 28 [2] 2c 28 [2] 13 34 }

  condition:
    any of them
}