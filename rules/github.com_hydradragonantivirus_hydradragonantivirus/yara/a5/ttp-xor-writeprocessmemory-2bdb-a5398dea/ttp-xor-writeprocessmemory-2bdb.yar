rule TTP_XOR_WriteProcessMemory_2bdb {
  strings:
    $key_2bdb = { 7c a9 [2] 4e 8b [2] 48 be [2] 66 be [2] 59 a2 }

  condition:
    any of them
}