rule TTP_XOR_WriteProcessMemory_1cf5 {
  strings:
    $key_1cf5 = { 4b 87 [2] 79 a5 [2] 7f 90 [2] 51 90 [2] 6e 8c }

  condition:
    any of them
}