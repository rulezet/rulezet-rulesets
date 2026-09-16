rule TTP_XOR_WriteProcessMemory_ede8 {
  strings:
    $key_ede8 = { ba 9a [2] 88 b8 [2] 8e 8d [2] a0 8d [2] 9f 91 }

  condition:
    any of them
}