rule TTP_XOR_WriteProcessMemory_69e5 {
  strings:
    $key_69e5 = { 3e 97 [2] 0c b5 [2] 0a 80 [2] 24 80 [2] 1b 9c }

  condition:
    any of them
}