rule TTP_XOR_WriteProcessMemory_2d47 {
  strings:
    $key_2d47 = { 7a 35 [2] 48 17 [2] 4e 22 [2] 60 22 [2] 5f 3e }

  condition:
    any of them
}