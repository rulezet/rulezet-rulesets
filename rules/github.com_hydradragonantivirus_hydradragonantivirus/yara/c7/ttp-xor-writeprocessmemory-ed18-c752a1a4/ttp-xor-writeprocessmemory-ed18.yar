rule TTP_XOR_WriteProcessMemory_ed18 {
  strings:
    $key_ed18 = { ba 6a [2] 88 48 [2] 8e 7d [2] a0 7d [2] 9f 61 }

  condition:
    any of them
}