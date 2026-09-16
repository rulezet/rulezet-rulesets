rule TTP_XOR_WriteProcessMemory_eddb {
  strings:
    $key_eddb = { ba a9 [2] 88 8b [2] 8e be [2] a0 be [2] 9f a2 }

  condition:
    any of them
}