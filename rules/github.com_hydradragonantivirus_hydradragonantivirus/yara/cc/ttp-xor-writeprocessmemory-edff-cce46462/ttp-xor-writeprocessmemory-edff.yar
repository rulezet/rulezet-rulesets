rule TTP_XOR_WriteProcessMemory_edff {
  strings:
    $key_edff = { ba 8d [2] 88 af [2] 8e 9a [2] a0 9a [2] 9f 86 }

  condition:
    any of them
}