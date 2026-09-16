rule TTP_XOR_WriteProcessMemory_2912 {
  strings:
    $key_2912 = { 7e 60 [2] 4c 42 [2] 4a 77 [2] 64 77 [2] 5b 6b }

  condition:
    any of them
}