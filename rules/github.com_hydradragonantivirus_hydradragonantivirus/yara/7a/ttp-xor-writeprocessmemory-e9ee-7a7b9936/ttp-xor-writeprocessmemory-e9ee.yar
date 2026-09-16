rule TTP_XOR_WriteProcessMemory_e9ee {
  strings:
    $key_e9ee = { be 9c [2] 8c be [2] 8a 8b [2] a4 8b [2] 9b 97 }

  condition:
    any of them
}