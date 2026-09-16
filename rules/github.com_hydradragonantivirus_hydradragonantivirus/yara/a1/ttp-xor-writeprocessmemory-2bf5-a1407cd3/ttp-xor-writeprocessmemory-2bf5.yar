rule TTP_XOR_WriteProcessMemory_2bf5 {
  strings:
    $key_2bf5 = { 7c 87 [2] 4e a5 [2] 48 90 [2] 66 90 [2] 59 8c }

  condition:
    any of them
}