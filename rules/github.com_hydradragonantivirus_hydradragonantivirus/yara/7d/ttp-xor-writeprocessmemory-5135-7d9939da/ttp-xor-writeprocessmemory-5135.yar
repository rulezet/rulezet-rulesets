rule TTP_XOR_WriteProcessMemory_5135 {
  strings:
    $key_5135 = { 06 47 [2] 34 65 [2] 32 50 [2] 1c 50 [2] 23 4c }

  condition:
    any of them
}