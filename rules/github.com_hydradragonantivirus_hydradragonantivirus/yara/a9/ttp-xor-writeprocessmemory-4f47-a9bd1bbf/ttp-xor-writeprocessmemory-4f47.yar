rule TTP_XOR_WriteProcessMemory_4f47 {
  strings:
    $key_4f47 = { 18 35 [2] 2a 17 [2] 2c 22 [2] 02 22 [2] 3d 3e }

  condition:
    any of them
}