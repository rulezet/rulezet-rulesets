rule TTP_XOR_WriteProcessMemory_36e5 {
  strings:
    $key_36e5 = { 61 97 [2] 53 b5 [2] 55 80 [2] 7b 80 [2] 44 9c }

  condition:
    any of them
}