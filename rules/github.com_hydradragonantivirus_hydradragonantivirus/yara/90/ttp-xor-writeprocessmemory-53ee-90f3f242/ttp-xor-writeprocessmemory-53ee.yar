rule TTP_XOR_WriteProcessMemory_53ee {
  strings:
    $key_53ee = { 04 9c [2] 36 be [2] 30 8b [2] 1e 8b [2] 21 97 }

  condition:
    any of them
}