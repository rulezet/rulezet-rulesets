rule TTP_XOR_WriteProcessMemory_29e5 {
  strings:
    $key_29e5 = { 7e 97 [2] 4c b5 [2] 4a 80 [2] 64 80 [2] 5b 9c }

  condition:
    any of them
}