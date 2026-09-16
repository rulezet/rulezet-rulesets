rule TTP_XOR_WriteProcessMemory_59ee {
  strings:
    $key_59ee = { 0e 9c [2] 3c be [2] 3a 8b [2] 14 8b [2] 2b 97 }

  condition:
    any of them
}