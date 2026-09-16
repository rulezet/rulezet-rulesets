rule TTP_XOR_WriteProcessMemory_a991 {
  strings:
    $key_a991 = { fe e3 [2] cc c1 [2] ca f4 [2] e4 f4 [2] db e8 }

  condition:
    any of them
}