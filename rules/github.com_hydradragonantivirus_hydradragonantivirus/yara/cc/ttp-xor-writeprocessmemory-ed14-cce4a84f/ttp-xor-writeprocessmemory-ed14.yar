rule TTP_XOR_WriteProcessMemory_ed14 {
  strings:
    $key_ed14 = { ba 66 [2] 88 44 [2] 8e 71 [2] a0 71 [2] 9f 6d }

  condition:
    any of them
}