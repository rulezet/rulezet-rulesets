rule TTP_XOR_WriteProcessMemory_1e77 {
  strings:
    $key_1e77 = { 49 05 [2] 7b 27 [2] 7d 12 [2] 53 12 [2] 6c 0e }

  condition:
    any of them
}