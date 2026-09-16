rule TTP_XOR_WriteProcessMemory_b8d3 {
  strings:
    $key_b8d3 = { ef a1 [2] dd 83 [2] db b6 [2] f5 b6 [2] ca aa }

  condition:
    any of them
}