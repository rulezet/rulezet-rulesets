rule TTP_XOR_WriteProcessMemory_2e47 {
  strings:
    $key_2e47 = { 79 35 [2] 4b 17 [2] 4d 22 [2] 63 22 [2] 5c 3e }

  condition:
    any of them
}