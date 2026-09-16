rule TTP_XOR_WriteProcessMemory_2965 {
  strings:
    $key_2965 = { 7e 17 [2] 4c 35 [2] 4a 00 [2] 64 00 [2] 5b 1c }

  condition:
    any of them
}