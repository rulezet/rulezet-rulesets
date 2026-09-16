rule TTP_XOR_WriteProcessMemory_24e5 {
  strings:
    $key_24e5 = { 73 97 [2] 41 b5 [2] 47 80 [2] 69 80 [2] 56 9c }

  condition:
    any of them
}