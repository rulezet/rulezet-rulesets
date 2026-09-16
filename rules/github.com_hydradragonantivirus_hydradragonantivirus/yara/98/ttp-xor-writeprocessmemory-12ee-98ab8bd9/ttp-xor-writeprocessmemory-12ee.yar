rule TTP_XOR_WriteProcessMemory_12ee {
  strings:
    $key_12ee = { 45 9c [2] 77 be [2] 71 8b [2] 5f 8b [2] 60 97 }

  condition:
    any of them
}