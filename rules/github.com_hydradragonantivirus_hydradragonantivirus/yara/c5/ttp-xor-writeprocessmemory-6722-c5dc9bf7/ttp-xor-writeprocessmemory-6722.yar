rule TTP_XOR_WriteProcessMemory_6722 {
  strings:
    $key_6722 = { 30 50 [2] 02 72 [2] 04 47 [2] 2a 47 [2] 15 5b }

  condition:
    any of them
}