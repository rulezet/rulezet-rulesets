rule TTP_XOR_WriteProcessMemory_7cdb {
  strings:
    $key_7cdb = { 2b a9 [2] 19 8b [2] 1f be [2] 31 be [2] 0e a2 }

  condition:
    any of them
}