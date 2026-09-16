rule TTP_XOR_WriteProcessMemory_2924 {
  strings:
    $key_2924 = { 7e 56 [2] 4c 74 [2] 4a 41 [2] 64 41 [2] 5b 5d }

  condition:
    any of them
}