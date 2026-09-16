rule TTP_XOR_WriteProcessMemory_4ef3 {
  strings:
    $key_4ef3 = { 19 81 [2] 2b a3 [2] 2d 96 [2] 03 96 [2] 3c 8a }

  condition:
    any of them
}