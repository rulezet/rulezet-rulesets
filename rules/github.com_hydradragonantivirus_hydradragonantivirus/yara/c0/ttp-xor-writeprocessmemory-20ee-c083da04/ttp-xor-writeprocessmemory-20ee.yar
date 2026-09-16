rule TTP_XOR_WriteProcessMemory_20ee {
  strings:
    $key_20ee = { 77 9c [2] 45 be [2] 43 8b [2] 6d 8b [2] 52 97 }

  condition:
    any of them
}