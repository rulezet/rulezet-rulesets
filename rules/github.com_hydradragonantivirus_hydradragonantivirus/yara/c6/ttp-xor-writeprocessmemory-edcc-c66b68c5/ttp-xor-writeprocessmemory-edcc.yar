rule TTP_XOR_WriteProcessMemory_edcc {
  strings:
    $key_edcc = { ba be [2] 88 9c [2] 8e a9 [2] a0 a9 [2] 9f b5 }

  condition:
    any of them
}