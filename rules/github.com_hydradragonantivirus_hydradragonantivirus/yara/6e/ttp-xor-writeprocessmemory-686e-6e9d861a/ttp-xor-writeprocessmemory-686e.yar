rule TTP_XOR_WriteProcessMemory_686e {
  strings:
    $key_686e = { 3f 1c [2] 0d 3e [2] 0b 0b [2] 25 0b [2] 1a 17 }

  condition:
    any of them
}