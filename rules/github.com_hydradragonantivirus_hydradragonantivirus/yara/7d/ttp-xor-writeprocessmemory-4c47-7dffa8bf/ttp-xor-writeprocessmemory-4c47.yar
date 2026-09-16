rule TTP_XOR_WriteProcessMemory_4c47 {
  strings:
    $key_4c47 = { 1b 35 [2] 29 17 [2] 2f 22 [2] 01 22 [2] 3e 3e }

  condition:
    any of them
}