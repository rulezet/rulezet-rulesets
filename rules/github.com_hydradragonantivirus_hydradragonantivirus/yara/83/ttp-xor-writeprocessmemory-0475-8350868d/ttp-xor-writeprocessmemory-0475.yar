rule TTP_XOR_WriteProcessMemory_0475 {
  strings:
    $key_0475 = { 53 07 [2] 61 25 [2] 67 10 [2] 49 10 [2] 76 0c }

  condition:
    any of them
}