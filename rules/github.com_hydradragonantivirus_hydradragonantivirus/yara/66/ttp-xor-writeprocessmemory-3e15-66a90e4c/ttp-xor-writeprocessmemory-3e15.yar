rule TTP_XOR_WriteProcessMemory_3e15 {
  strings:
    $key_3e15 = { 69 67 [2] 5b 45 [2] 5d 70 [2] 73 70 [2] 4c 6c }

  condition:
    any of them
}