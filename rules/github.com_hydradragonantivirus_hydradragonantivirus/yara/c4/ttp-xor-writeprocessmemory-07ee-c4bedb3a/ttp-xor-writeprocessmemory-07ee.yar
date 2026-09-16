rule TTP_XOR_WriteProcessMemory_07ee {
  strings:
    $key_07ee = { 50 9c [2] 62 be [2] 64 8b [2] 4a 8b [2] 75 97 }

  condition:
    any of them
}