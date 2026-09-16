rule TTP_XOR_WriteProcessMemory_30ee {
  strings:
    $key_30ee = { 67 9c [2] 55 be [2] 53 8b [2] 7d 8b [2] 42 97 }

  condition:
    any of them
}