rule TTP_XOR_WriteProcessMemory_39e5 {
  strings:
    $key_39e5 = { 6e 97 [2] 5c b5 [2] 5a 80 [2] 74 80 [2] 4b 9c }

  condition:
    any of them
}