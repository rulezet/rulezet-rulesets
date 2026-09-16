rule TTP_XOR_WriteProcessMemory_edcb {
  strings:
    $key_edcb = { ba b9 [2] 88 9b [2] 8e ae [2] a0 ae [2] 9f b2 }

  condition:
    any of them
}