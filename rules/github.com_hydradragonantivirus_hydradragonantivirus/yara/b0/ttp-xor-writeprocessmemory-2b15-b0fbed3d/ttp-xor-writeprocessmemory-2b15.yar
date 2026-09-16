rule TTP_XOR_WriteProcessMemory_2b15 {
  strings:
    $key_2b15 = { 7c 67 [2] 4e 45 [2] 48 70 [2] 66 70 [2] 59 6c }

  condition:
    any of them
}