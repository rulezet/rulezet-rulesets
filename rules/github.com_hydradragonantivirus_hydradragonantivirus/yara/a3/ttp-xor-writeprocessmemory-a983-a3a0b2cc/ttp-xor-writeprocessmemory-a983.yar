rule TTP_XOR_WriteProcessMemory_a983 {
  strings:
    $key_a983 = { fe f1 [2] cc d3 [2] ca e6 [2] e4 e6 [2] db fa }

  condition:
    any of them
}