rule TTP_XOR_WriteProcessMemory_2946 {
  strings:
    $key_2946 = { 7e 34 [2] 4c 16 [2] 4a 23 [2] 64 23 [2] 5b 3f }

  condition:
    any of them
}