rule TTP_XOR_WriteProcessMemory_046e {
  strings:
    $key_046e = { 53 1c [2] 61 3e [2] 67 0b [2] 49 0b [2] 76 17 }

  condition:
    any of them
}