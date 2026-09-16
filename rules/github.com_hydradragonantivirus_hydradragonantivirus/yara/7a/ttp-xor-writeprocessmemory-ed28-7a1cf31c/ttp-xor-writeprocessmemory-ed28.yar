rule TTP_XOR_WriteProcessMemory_ed28 {
  strings:
    $key_ed28 = { ba 5a [2] 88 78 [2] 8e 4d [2] a0 4d [2] 9f 51 }

  condition:
    any of them
}