rule TTP_XOR_WriteProcessMemory_0a75 {
  strings:
    $key_0a75 = { 5d 07 [2] 6f 25 [2] 69 10 [2] 47 10 [2] 78 0c }

  condition:
    any of them
}