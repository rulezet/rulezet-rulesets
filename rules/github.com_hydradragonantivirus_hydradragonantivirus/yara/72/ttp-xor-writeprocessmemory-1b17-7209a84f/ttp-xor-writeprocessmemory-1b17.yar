rule TTP_XOR_WriteProcessMemory_1b17 {
  strings:
    $key_1b17 = { 4c 65 [2] 7e 47 [2] 78 72 [2] 56 72 [2] 69 6e }

  condition:
    any of them
}