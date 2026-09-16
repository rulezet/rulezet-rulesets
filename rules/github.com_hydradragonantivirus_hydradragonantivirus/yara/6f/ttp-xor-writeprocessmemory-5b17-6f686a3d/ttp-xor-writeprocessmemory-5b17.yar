rule TTP_XOR_WriteProcessMemory_5b17 {
  strings:
    $key_5b17 = { 0c 65 [2] 3e 47 [2] 38 72 [2] 16 72 [2] 29 6e }

  condition:
    any of them
}