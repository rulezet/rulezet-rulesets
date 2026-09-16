rule TTP_XOR_WriteProcessMemory_01ee {
  strings:
    $key_01ee = { 56 9c [2] 64 be [2] 62 8b [2] 4c 8b [2] 73 97 }

  condition:
    any of them
}