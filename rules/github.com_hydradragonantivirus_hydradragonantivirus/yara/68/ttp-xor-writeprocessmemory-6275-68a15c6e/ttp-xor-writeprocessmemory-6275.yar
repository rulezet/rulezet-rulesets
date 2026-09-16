rule TTP_XOR_WriteProcessMemory_6275 {
  strings:
    $key_6275 = { 35 07 [2] 07 25 [2] 01 10 [2] 2f 10 [2] 10 0c }

  condition:
    any of them
}