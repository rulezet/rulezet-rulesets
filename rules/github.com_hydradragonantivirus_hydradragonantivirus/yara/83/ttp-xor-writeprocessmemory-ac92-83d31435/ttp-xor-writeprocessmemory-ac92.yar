rule TTP_XOR_WriteProcessMemory_ac92 {
  strings:
    $key_ac92 = { fb e0 [2] c9 c2 [2] cf f7 [2] e1 f7 [2] de eb }

  condition:
    any of them
}