rule TTP_XOR_WriteProcessMemory_4c10 {
  strings:
    $key_4c10 = { 1b 62 [2] 29 40 [2] 2f 75 [2] 01 75 [2] 3e 69 }

  condition:
    any of them
}