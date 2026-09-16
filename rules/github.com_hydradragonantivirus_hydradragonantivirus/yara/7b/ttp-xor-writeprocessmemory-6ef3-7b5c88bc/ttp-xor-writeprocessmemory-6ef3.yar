rule TTP_XOR_WriteProcessMemory_6ef3 {
  strings:
    $key_6ef3 = { 39 81 [2] 0b a3 [2] 0d 96 [2] 23 96 [2] 1c 8a }

  condition:
    any of them
}