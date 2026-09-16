rule TTP_XOR_WriteProcessMemory_7975 {
  strings:
    $key_7975 = { 2e 07 [2] 1c 25 [2] 1a 10 [2] 34 10 [2] 0b 0c }

  condition:
    any of them
}