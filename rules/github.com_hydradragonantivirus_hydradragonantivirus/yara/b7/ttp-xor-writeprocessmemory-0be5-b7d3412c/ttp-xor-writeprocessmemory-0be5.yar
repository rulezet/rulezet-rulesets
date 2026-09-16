rule TTP_XOR_WriteProcessMemory_0be5 {
  strings:
    $key_0be5 = { 5c 97 [2] 6e b5 [2] 68 80 [2] 46 80 [2] 79 9c }

  condition:
    any of them
}