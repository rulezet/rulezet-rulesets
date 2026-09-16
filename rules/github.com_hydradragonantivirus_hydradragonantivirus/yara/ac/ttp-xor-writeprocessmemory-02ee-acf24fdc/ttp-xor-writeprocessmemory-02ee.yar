rule TTP_XOR_WriteProcessMemory_02ee {
  strings:
    $key_02ee = { 55 9c [2] 67 be [2] 61 8b [2] 4f 8b [2] 70 97 }

  condition:
    any of them
}