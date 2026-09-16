rule TTP_XOR_WriteProcessMemory_7930 {
  strings:
    $key_7930 = { 2e 42 [2] 1c 60 [2] 1a 55 [2] 34 55 [2] 0b 49 }

  condition:
    any of them
}