rule TTP_XOR_WriteProcessMemory_edbb {
  strings:
    $key_edbb = { ba c9 [2] 88 eb [2] 8e de [2] a0 de [2] 9f c2 }

  condition:
    any of them
}