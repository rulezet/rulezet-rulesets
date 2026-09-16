rule TTP_XOR_WriteProcessMemory_2c1d {
  strings:
    $key_2c1d = { 7b 6f [2] 49 4d [2] 4f 78 [2] 61 78 [2] 5e 64 }

  condition:
    any of them
}