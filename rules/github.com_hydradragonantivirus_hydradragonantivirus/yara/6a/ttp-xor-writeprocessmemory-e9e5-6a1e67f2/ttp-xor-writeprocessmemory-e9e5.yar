rule TTP_XOR_WriteProcessMemory_e9e5 {
  strings:
    $key_e9e5 = { be 97 [2] 8c b5 [2] 8a 80 [2] a4 80 [2] 9b 9c }

  condition:
    any of them
}