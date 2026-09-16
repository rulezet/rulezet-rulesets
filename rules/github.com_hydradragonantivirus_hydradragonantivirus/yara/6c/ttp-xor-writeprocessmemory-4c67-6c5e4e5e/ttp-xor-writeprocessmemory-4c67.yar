rule TTP_XOR_WriteProcessMemory_4c67 {
  strings:
    $key_4c67 = { 1b 15 [2] 29 37 [2] 2f 02 [2] 01 02 [2] 3e 1e }

  condition:
    any of them
}