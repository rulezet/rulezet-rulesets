rule TTP_XOR_WriteProcessMemory_2be5 {
  strings:
    $key_2be5 = { 7c 97 [2] 4e b5 [2] 48 80 [2] 66 80 [2] 59 9c }

  condition:
    any of them
}