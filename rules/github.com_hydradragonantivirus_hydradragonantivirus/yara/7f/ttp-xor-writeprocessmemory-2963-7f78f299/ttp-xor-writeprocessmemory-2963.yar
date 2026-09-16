rule TTP_XOR_WriteProcessMemory_2963 {
  strings:
    $key_2963 = { 7e 11 [2] 4c 33 [2] 4a 06 [2] 64 06 [2] 5b 1a }

  condition:
    any of them
}