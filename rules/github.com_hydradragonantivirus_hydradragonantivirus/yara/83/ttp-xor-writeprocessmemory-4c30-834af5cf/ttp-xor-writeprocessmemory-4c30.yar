rule TTP_XOR_WriteProcessMemory_4c30 {
  strings:
    $key_4c30 = { 1b 42 [2] 29 60 [2] 2f 55 [2] 01 55 [2] 3e 49 }

  condition:
    any of them
}