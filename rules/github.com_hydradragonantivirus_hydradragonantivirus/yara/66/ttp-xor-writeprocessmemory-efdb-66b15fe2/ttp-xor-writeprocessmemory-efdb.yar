rule TTP_XOR_WriteProcessMemory_efdb {
  strings:
    $key_efdb = { b8 a9 [2] 8a 8b [2] 8c be [2] a2 be [2] 9d a2 }

  condition:
    any of them
}