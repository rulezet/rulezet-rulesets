rule TTP_XOR_WriteProcessMemory_c975 {
  strings:
    $key_c975 = { 9e 07 [2] ac 25 [2] aa 10 [2] 84 10 [2] bb 0c }

  condition:
    any of them
}