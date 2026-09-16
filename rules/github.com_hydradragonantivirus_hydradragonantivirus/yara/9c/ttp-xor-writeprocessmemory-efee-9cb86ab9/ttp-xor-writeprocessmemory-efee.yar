rule TTP_XOR_WriteProcessMemory_efee {
  strings:
    $key_efee = { b8 9c [2] 8a be [2] 8c 8b [2] a2 8b [2] 9d 97 }

  condition:
    any of them
}