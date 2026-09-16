rule TTP_XOR_WriteProcessMemory_05ee {
  strings:
    $key_05ee = { 52 9c [2] 60 be [2] 66 8b [2] 48 8b [2] 77 97 }

  condition:
    any of them
}