rule TTP_XOR_WriteProcessMemory_2c44 {
  strings:
    $key_2c44 = { 7b 36 [2] 49 14 [2] 4f 21 [2] 61 21 [2] 5e 3d }

  condition:
    any of them
}