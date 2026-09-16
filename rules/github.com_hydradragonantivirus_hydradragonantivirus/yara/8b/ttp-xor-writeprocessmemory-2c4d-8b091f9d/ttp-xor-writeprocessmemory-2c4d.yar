rule TTP_XOR_WriteProcessMemory_2c4d {
  strings:
    $key_2c4d = { 7b 3f [2] 49 1d [2] 4f 28 [2] 61 28 [2] 5e 34 }

  condition:
    any of them
}