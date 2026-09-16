rule TTP_XOR_WriteProcessMemory_2967 {
  strings:
    $key_2967 = { 7e 15 [2] 4c 37 [2] 4a 02 [2] 64 02 [2] 5b 1e }

  condition:
    any of them
}