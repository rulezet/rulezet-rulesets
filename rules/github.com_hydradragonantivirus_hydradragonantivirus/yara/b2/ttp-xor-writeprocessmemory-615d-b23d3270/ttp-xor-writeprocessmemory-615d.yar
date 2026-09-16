rule TTP_XOR_WriteProcessMemory_615d {
  strings:
    $key_615d = { 36 2f [2] 04 0d [2] 02 38 [2] 2c 38 [2] 13 24 }

  condition:
    any of them
}