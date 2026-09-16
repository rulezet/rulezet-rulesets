rule TTP_XOR_WriteProcessMemory_edec {
  strings:
    $key_edec = { ba 9e [2] 88 bc [2] 8e 89 [2] a0 89 [2] 9f 95 }

  condition:
    any of them
}