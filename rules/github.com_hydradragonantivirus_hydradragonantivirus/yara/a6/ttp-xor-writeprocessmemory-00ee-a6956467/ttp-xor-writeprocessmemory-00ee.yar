rule TTP_XOR_WriteProcessMemory_00ee {
  strings:
    $key_00ee = { 57 9c [2] 65 be [2] 63 8b [2] 4d 8b [2] 72 97 }

  condition:
    any of them
}