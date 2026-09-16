rule TTP_XOR_WriteProcessMemory_2940 {
  strings:
    $key_2940 = { 7e 32 [2] 4c 10 [2] 4a 25 [2] 64 25 [2] 5b 39 }

  condition:
    any of them
}