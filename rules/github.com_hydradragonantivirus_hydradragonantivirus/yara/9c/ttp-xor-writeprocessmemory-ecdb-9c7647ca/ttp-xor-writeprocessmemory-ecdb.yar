rule TTP_XOR_WriteProcessMemory_ecdb {
  strings:
    $key_ecdb = { bb a9 [2] 89 8b [2] 8f be [2] a1 be [2] 9e a2 }

  condition:
    any of them
}