rule TTP_XOR_WriteProcessMemory_21ee {
  strings:
    $key_21ee = { 76 9c [2] 44 be [2] 42 8b [2] 6c 8b [2] 53 97 }

  condition:
    any of them
}