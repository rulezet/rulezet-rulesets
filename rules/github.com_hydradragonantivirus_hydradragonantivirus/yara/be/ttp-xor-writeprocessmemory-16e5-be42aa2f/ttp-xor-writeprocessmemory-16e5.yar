rule TTP_XOR_WriteProcessMemory_16e5 {
  strings:
    $key_16e5 = { 41 97 [2] 73 b5 [2] 75 80 [2] 5b 80 [2] 64 9c }

  condition:
    any of them
}