rule TTP_XOR_WriteProcessMemory_67ed {
  strings:
    $key_67ed = { 30 9f [2] 02 bd [2] 04 88 [2] 2a 88 [2] 15 94 }

  condition:
    any of them
}