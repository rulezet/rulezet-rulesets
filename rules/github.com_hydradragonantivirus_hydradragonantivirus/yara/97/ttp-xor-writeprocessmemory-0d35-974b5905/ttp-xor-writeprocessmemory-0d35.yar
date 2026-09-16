rule TTP_XOR_WriteProcessMemory_0d35 {
  strings:
    $key_0d35 = { 5a 47 [2] 68 65 [2] 6e 50 [2] 40 50 [2] 7f 4c }

  condition:
    any of them
}