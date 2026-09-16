rule TTP_XOR_WriteProcessMemory_2165 {
  strings:
    $key_2165 = { 76 17 [2] 44 35 [2] 42 00 [2] 6c 00 [2] 53 1c }

  condition:
    any of them
}