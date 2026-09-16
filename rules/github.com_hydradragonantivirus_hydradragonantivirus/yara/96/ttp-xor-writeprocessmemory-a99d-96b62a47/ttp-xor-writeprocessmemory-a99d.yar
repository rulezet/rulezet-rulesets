rule TTP_XOR_WriteProcessMemory_a99d {
  strings:
    $key_a99d = { fe ef [2] cc cd [2] ca f8 [2] e4 f8 [2] db e4 }

  condition:
    any of them
}