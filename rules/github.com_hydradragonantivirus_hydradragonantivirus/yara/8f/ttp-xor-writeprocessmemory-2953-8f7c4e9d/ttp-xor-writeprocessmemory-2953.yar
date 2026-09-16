rule TTP_XOR_WriteProcessMemory_2953 {
  strings:
    $key_2953 = { 7e 21 [2] 4c 03 [2] 4a 36 [2] 64 36 [2] 5b 2a }

  condition:
    any of them
}