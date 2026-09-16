rule TTP_XOR_WriteProcessMemory_03ee {
  strings:
    $key_03ee = { 54 9c [2] 66 be [2] 60 8b [2] 4e 8b [2] 71 97 }

  condition:
    any of them
}