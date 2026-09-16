rule TTP_XOR_WriteProcessMemory_3cdb {
  strings:
    $key_3cdb = { 6b a9 [2] 59 8b [2] 5f be [2] 71 be [2] 4e a2 }

  condition:
    any of them
}