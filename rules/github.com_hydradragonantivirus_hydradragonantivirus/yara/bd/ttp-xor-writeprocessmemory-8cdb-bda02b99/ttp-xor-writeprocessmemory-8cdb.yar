rule TTP_XOR_WriteProcessMemory_8cdb {
  strings:
    $key_8cdb = { db a9 [2] e9 8b [2] ef be [2] c1 be [2] fe a2 }

  condition:
    any of them
}