rule TTP_XOR_WriteProcessMemory_47ee {
  strings:
    $key_47ee = { 10 9c [2] 22 be [2] 24 8b [2] 0a 8b [2] 35 97 }

  condition:
    any of them
}