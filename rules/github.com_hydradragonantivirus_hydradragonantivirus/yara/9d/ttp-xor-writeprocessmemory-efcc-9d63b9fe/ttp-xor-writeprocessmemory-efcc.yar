rule TTP_XOR_WriteProcessMemory_efcc {
  strings:
    $key_efcc = { b8 be [2] 8a 9c [2] 8c a9 [2] a2 a9 [2] 9d b5 }

  condition:
    any of them
}