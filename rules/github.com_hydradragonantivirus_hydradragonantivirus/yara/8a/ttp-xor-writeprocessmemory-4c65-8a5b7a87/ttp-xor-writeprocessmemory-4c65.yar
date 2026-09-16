rule TTP_XOR_WriteProcessMemory_4c65 {
  strings:
    $key_4c65 = { 1b 17 [2] 29 35 [2] 2f 00 [2] 01 00 [2] 3e 1c }

  condition:
    any of them
}