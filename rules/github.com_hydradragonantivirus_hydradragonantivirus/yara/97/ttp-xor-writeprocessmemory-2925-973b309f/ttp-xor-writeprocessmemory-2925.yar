rule TTP_XOR_WriteProcessMemory_2925 {
  strings:
    $key_2925 = { 7e 57 [2] 4c 75 [2] 4a 40 [2] 64 40 [2] 5b 5c }

  condition:
    any of them
}