rule TTP_XOR_WriteProcessMemory_7938 {
  strings:
    $key_7938 = { 2e 4a [2] 1c 68 [2] 1a 5d [2] 34 5d [2] 0b 41 }

  condition:
    any of them
}