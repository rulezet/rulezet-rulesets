rule TTP_XOR_WriteProcessMemory_6945 {
  strings:
    $key_6945 = { 3e 37 [2] 0c 15 [2] 0a 20 [2] 24 20 [2] 1b 3c }

  condition:
    any of them
}