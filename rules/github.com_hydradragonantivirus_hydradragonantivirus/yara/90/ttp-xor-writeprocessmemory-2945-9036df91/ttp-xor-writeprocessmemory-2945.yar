rule TTP_XOR_WriteProcessMemory_2945 {
  strings:
    $key_2945 = { 7e 37 [2] 4c 15 [2] 4a 20 [2] 64 20 [2] 5b 3c }

  condition:
    any of them
}