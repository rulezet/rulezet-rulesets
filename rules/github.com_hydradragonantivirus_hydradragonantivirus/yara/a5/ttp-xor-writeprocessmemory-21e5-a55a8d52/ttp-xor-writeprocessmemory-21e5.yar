rule TTP_XOR_WriteProcessMemory_21e5 {
  strings:
    $key_21e5 = { 76 97 [2] 44 b5 [2] 42 80 [2] 6c 80 [2] 53 9c }

  condition:
    any of them
}