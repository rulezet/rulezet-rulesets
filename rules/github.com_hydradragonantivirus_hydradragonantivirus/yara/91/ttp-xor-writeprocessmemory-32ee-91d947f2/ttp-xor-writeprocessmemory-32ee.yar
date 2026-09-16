rule TTP_XOR_WriteProcessMemory_32ee {
  strings:
    $key_32ee = { 65 9c [2] 57 be [2] 51 8b [2] 7f 8b [2] 40 97 }

  condition:
    any of them
}