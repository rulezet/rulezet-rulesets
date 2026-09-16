rule TTP_XOR_WriteProcessMemory_c2db {
  strings:
    $key_c2db = { 95 a9 [2] a7 8b [2] a1 be [2] 8f be [2] b0 a2 }

  condition:
    any of them
}