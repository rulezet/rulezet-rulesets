rule TTP_XOR_WriteProcessMemory_37ee {
  strings:
    $key_37ee = { 60 9c [2] 52 be [2] 54 8b [2] 7a 8b [2] 45 97 }

  condition:
    any of them
}