rule TTP_XOR_WriteProcessMemory_4c31 {
  strings:
    $key_4c31 = { 1b 43 [2] 29 61 [2] 2f 54 [2] 01 54 [2] 3e 48 }

  condition:
    any of them
}