rule TTP_XOR_WriteProcessMemory_4a47 {
  strings:
    $key_4a47 = { 1d 35 [2] 2f 17 [2] 29 22 [2] 07 22 [2] 38 3e }

  condition:
    any of them
}