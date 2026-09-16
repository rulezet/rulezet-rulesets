rule TTP_XOR_WriteProcessMemory_5cdb {
  strings:
    $key_5cdb = { 0b a9 [2] 39 8b [2] 3f be [2] 11 be [2] 2e a2 }

  condition:
    any of them
}