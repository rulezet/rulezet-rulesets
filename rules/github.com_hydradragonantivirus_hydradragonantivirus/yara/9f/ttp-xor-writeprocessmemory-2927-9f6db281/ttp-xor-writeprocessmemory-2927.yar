rule TTP_XOR_WriteProcessMemory_2927 {
  strings:
    $key_2927 = { 7e 55 [2] 4c 77 [2] 4a 42 [2] 64 42 [2] 5b 5e }

  condition:
    any of them
}