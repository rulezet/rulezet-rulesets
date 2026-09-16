rule TTP_XOR_WriteProcessMemory_4c26 {
  strings:
    $key_4c26 = { 1b 54 [2] 29 76 [2] 2f 43 [2] 01 43 [2] 3e 5f }

  condition:
    any of them
}