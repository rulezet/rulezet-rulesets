rule TTP_XOR_WriteProcessMemory_2916 {
  strings:
    $key_2916 = { 7e 64 [2] 4c 46 [2] 4a 73 [2] 64 73 [2] 5b 6f }

  condition:
    any of them
}