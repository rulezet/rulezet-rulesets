rule TTP_XOR_WriteProcessMemory_a992 {
  strings:
    $key_a992 = { fe e0 [2] cc c2 [2] ca f7 [2] e4 f7 [2] db eb }

  condition:
    any of them
}