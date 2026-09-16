rule TTP_XOR_WriteProcessMemory_2ce5 {
  strings:
    $key_2ce5 = { 7b 97 [2] 49 b5 [2] 4f 80 [2] 61 80 [2] 5e 9c }

  condition:
    any of them
}