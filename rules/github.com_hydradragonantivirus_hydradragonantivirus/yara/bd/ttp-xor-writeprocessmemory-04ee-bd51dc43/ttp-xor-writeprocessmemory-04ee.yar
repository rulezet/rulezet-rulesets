rule TTP_XOR_WriteProcessMemory_04ee {
  strings:
    $key_04ee = { 53 9c [2] 61 be [2] 67 8b [2] 49 8b [2] 76 97 }

  condition:
    any of them
}