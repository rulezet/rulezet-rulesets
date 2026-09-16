rule TTP_XOR_WriteProcessMemory_6138 {
  strings:
    $key_6138 = { 36 4a [2] 04 68 [2] 02 5d [2] 2c 5d [2] 13 41 }

  condition:
    any of them
}