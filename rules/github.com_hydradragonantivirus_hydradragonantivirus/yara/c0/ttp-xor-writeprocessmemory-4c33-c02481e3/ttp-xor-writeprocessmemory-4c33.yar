rule TTP_XOR_WriteProcessMemory_4c33 {
  strings:
    $key_4c33 = { 1b 41 [2] 29 63 [2] 2f 56 [2] 01 56 [2] 3e 4a }

  condition:
    any of them
}