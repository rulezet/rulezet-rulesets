rule TTP_XOR_WriteProcessMemory_7c15 {
  strings:
    $key_7c15 = { 2b 67 [2] 19 45 [2] 1f 70 [2] 31 70 [2] 0e 6c }

  condition:
    any of them
}