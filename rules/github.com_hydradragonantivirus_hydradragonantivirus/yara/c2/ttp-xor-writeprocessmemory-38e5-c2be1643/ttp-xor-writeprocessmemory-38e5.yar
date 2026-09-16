rule TTP_XOR_WriteProcessMemory_38e5 {
  strings:
    $key_38e5 = { 6f 97 [2] 5d b5 [2] 5b 80 [2] 75 80 [2] 4a 9c }

  condition:
    any of them
}