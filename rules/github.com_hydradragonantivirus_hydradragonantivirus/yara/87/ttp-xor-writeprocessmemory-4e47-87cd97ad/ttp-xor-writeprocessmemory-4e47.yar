rule TTP_XOR_WriteProcessMemory_4e47 {
  strings:
    $key_4e47 = { 19 35 [2] 2b 17 [2] 2d 22 [2] 03 22 [2] 3c 3e }

  condition:
    any of them
}