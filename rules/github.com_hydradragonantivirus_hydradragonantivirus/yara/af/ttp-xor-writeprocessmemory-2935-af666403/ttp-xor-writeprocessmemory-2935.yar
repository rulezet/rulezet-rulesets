rule TTP_XOR_WriteProcessMemory_2935 {
  strings:
    $key_2935 = { 7e 47 [2] 4c 65 [2] 4a 50 [2] 64 50 [2] 5b 4c }

  condition:
    any of them
}