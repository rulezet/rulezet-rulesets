rule TTP_XOR_WriteProcessMemory_ed49 {
  strings:
    $key_ed49 = { ba 3b [2] 88 19 [2] 8e 2c [2] a0 2c [2] 9f 30 }

  condition:
    any of them
}