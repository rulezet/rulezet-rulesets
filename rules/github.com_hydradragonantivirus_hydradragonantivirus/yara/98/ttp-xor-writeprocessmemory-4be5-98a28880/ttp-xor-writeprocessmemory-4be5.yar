rule TTP_XOR_WriteProcessMemory_4be5 {
  strings:
    $key_4be5 = { 1c 97 [2] 2e b5 [2] 28 80 [2] 06 80 [2] 39 9c }

  condition:
    any of them
}