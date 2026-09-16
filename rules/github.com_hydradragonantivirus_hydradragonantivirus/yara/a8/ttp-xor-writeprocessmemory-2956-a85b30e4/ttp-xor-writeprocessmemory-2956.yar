rule TTP_XOR_WriteProcessMemory_2956 {
  strings:
    $key_2956 = { 7e 24 [2] 4c 06 [2] 4a 33 [2] 64 33 [2] 5b 2f }

  condition:
    any of them
}