rule TTP_XOR_WriteProcessMemory_7539 {
  strings:
    $key_7539 = { 22 4b [2] 10 69 [2] 16 5c [2] 38 5c [2] 07 40 }

  condition:
    any of them
}