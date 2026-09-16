rule TTP_XOR_WriteProcessMemory_0e47 {
  strings:
    $key_0e47 = { 59 35 [2] 6b 17 [2] 6d 22 [2] 43 22 [2] 7c 3e }

  condition:
    any of them
}