rule TTP_XOR_WriteProcessMemory_6910 {
  strings:
    $key_6910 = { 3e 62 [2] 0c 40 [2] 0a 75 [2] 24 75 [2] 1b 69 }

  condition:
    any of them
}