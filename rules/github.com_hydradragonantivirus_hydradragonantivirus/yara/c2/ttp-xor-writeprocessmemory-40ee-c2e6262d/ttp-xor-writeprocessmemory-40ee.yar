rule TTP_XOR_WriteProcessMemory_40ee {
  strings:
    $key_40ee = { 17 9c [2] 25 be [2] 23 8b [2] 0d 8b [2] 32 97 }

  condition:
    any of them
}