rule TTP_XOR_WriteProcessMemory_ed11 {
  strings:
    $key_ed11 = { ba 63 [2] 88 41 [2] 8e 74 [2] a0 74 [2] 9f 68 }

  condition:
    any of them
}