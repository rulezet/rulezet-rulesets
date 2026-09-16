rule TTP_XOR_WriteProcessMemory_ffdb {
  strings:
    $key_ffdb = { a8 a9 [2] 9a 8b [2] 9c be [2] b2 be [2] 8d a2 }

  condition:
    any of them
}