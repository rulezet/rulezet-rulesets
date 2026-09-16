rule TTP_XOR_WriteProcessMemory_76ee {
  strings:
    $key_76ee = { 21 9c [2] 13 be [2] 15 8b [2] 3b 8b [2] 04 97 }

  condition:
    any of them
}