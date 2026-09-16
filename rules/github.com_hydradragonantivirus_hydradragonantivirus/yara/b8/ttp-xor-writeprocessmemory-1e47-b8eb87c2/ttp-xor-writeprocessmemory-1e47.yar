rule TTP_XOR_WriteProcessMemory_1e47 {
  strings:
    $key_1e47 = { 49 35 [2] 7b 17 [2] 7d 22 [2] 53 22 [2] 6c 3e }

  condition:
    any of them
}