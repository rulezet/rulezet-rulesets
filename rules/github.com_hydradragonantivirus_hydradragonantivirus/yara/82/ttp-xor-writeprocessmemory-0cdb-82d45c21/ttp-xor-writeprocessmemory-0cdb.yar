rule TTP_XOR_WriteProcessMemory_0cdb {
  strings:
    $key_0cdb = { 5b a9 [2] 69 8b [2] 6f be [2] 41 be [2] 7e a2 }

  condition:
    any of them
}