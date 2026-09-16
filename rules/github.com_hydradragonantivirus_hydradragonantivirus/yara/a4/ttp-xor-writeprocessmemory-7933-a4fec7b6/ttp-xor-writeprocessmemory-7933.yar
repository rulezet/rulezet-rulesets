rule TTP_XOR_WriteProcessMemory_7933 {
  strings:
    $key_7933 = { 2e 41 [2] 1c 63 [2] 1a 56 [2] 34 56 [2] 0b 4a }

  condition:
    any of them
}