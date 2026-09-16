rule TTP_XOR_WriteProcessMemory_7e47 {
  strings:
    $key_7e47 = { 29 35 [2] 1b 17 [2] 1d 22 [2] 33 22 [2] 0c 3e }

  condition:
    any of them
}