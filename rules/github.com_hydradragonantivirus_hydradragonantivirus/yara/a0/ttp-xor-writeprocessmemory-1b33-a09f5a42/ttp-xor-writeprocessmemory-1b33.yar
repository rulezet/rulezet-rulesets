rule TTP_XOR_WriteProcessMemory_1b33 {
  strings:
    $key_1b33 = { 4c 41 [2] 7e 63 [2] 78 56 [2] 56 56 [2] 69 4a }

  condition:
    any of them
}