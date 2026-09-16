rule TTP_XOR_WriteProcessMemory_6bf5 {
  strings:
    $key_6bf5 = { 3c 87 [2] 0e a5 [2] 08 90 [2] 26 90 [2] 19 8c }

  condition:
    any of them
}