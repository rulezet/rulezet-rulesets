rule TTP_XOR_WriteProcessMemory_ed1d {
  strings:
    $key_ed1d = { ba 6f [2] 88 4d [2] 8e 78 [2] a0 78 [2] 9f 64 }

  condition:
    any of them
}