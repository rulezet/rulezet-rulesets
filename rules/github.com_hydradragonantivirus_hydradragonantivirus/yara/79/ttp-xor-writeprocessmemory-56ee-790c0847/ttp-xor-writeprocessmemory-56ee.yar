rule TTP_XOR_WriteProcessMemory_56ee {
  strings:
    $key_56ee = { 01 9c [2] 33 be [2] 35 8b [2] 1b 8b [2] 24 97 }

  condition:
    any of them
}