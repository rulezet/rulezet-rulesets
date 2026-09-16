rule TTP_XOR_WriteProcessMemory_cbdb {
  strings:
    $key_cbdb = { 9c a9 [2] ae 8b [2] a8 be [2] 86 be [2] b9 a2 }

  condition:
    any of them
}