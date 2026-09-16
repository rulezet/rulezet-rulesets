rule TTP_XOR_WriteProcessMemory_1669 {
  strings:
    $key_1669 = { 41 1b [2] 73 39 [2] 75 0c [2] 5b 0c [2] 64 10 }

  condition:
    any of them
}