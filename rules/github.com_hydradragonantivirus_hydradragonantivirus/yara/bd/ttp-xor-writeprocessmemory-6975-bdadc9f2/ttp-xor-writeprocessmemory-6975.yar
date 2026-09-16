rule TTP_XOR_WriteProcessMemory_6975 {
  strings:
    $key_6975 = { 3e 07 [2] 0c 25 [2] 0a 10 [2] 24 10 [2] 1b 0c }

  condition:
    any of them
}