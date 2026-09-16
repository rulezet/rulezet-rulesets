rule TTP_XOR_WriteProcessMemory_2933 {
  strings:
    $key_2933 = { 7e 41 [2] 4c 63 [2] 4a 56 [2] 64 56 [2] 5b 4a }

  condition:
    any of them
}