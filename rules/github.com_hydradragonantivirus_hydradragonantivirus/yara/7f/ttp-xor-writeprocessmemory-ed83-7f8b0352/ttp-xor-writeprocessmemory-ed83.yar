rule TTP_XOR_WriteProcessMemory_ed83 {
  strings:
    $key_ed83 = { ba f1 [2] 88 d3 [2] 8e e6 [2] a0 e6 [2] 9f fa }

  condition:
    any of them
}