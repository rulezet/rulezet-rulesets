rule TTP_XOR_WriteProcessMemory_623b {
  strings:
    $key_623b = { 35 49 [2] 07 6b [2] 01 5e [2] 2f 5e [2] 10 42 }

  condition:
    any of them
}