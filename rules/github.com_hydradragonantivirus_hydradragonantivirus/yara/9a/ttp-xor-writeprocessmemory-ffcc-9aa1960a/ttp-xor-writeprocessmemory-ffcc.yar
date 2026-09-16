rule TTP_XOR_WriteProcessMemory_ffcc {
  strings:
    $key_ffcc = { a8 be [2] 9a 9c [2] 9c a9 [2] b2 a9 [2] 8d b5 }

  condition:
    any of them
}