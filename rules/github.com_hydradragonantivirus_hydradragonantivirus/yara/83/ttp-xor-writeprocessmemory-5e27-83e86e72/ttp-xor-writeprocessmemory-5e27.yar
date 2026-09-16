rule TTP_XOR_WriteProcessMemory_5e27 {
  strings:
    $key_5e27 = { 09 55 [2] 3b 77 [2] 3d 42 [2] 13 42 [2] 2c 5e }

  condition:
    any of them
}