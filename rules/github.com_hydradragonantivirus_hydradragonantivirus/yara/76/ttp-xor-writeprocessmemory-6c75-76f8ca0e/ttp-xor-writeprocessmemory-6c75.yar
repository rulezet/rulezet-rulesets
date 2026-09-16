rule TTP_XOR_WriteProcessMemory_6c75 {
  strings:
    $key_6c75 = { 3b 07 [2] 09 25 [2] 0f 10 [2] 21 10 [2] 1e 0c }

  condition:
    any of them
}