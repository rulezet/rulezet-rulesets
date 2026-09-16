rule TTP_XOR_WriteProcessMemory_087e {
  strings:
    $key_087e = { 5f 0c [2] 6d 2e [2] 6b 1b [2] 45 1b [2] 7a 07 }

  condition:
    any of them
}