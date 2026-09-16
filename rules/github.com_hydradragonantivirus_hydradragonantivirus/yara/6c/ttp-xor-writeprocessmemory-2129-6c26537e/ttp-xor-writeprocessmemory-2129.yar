rule TTP_XOR_WriteProcessMemory_2129 {
  strings:
    $key_2129 = { 76 5b [2] 44 79 [2] 42 4c [2] 6c 4c [2] 53 50 }

  condition:
    any of them
}