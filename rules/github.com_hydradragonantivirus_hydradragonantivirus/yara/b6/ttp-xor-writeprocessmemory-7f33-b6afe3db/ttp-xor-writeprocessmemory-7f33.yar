rule TTP_XOR_WriteProcessMemory_7f33 {
  strings:
    $key_7f33 = { 28 41 [2] 1a 63 [2] 1c 56 [2] 32 56 [2] 0d 4a }

  condition:
    any of them
}