rule TTP_XOR_WriteProcessMemory_ed75 {
  strings:
    $key_ed75 = { ba 07 [2] 88 25 [2] 8e 10 [2] a0 10 [2] 9f 0c }

  condition:
    any of them
}