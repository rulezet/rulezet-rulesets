rule TTP_XOR_WriteProcessMemory_35ee {
  strings:
    $key_35ee = { 62 9c [2] 50 be [2] 56 8b [2] 78 8b [2] 47 97 }

  condition:
    any of them
}