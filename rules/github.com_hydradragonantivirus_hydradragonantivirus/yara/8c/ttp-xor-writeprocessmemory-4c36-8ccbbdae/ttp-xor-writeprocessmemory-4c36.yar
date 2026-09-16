rule TTP_XOR_WriteProcessMemory_4c36 {
  strings:
    $key_4c36 = { 1b 44 [2] 29 66 [2] 2f 53 [2] 01 53 [2] 3e 4f }

  condition:
    any of them
}