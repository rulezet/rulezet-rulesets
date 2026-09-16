rule TTP_XOR_WriteProcessMemory_5b73 {
  strings:
    $key_5b73 = { 0c 01 [2] 3e 23 [2] 38 16 [2] 16 16 [2] 29 0a }

  condition:
    any of them
}