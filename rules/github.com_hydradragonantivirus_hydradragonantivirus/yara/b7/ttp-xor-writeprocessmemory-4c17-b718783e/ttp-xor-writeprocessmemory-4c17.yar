rule TTP_XOR_WriteProcessMemory_4c17 {
  strings:
    $key_4c17 = { 1b 65 [2] 29 47 [2] 2f 72 [2] 01 72 [2] 3e 6e }

  condition:
    any of them
}