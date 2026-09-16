rule TTP_XOR_WriteProcessMemory_dd94 {
  strings:
    $key_dd94 = { 8a e6 [2] b8 c4 [2] be f1 [2] 90 f1 [2] af ed }

  condition:
    any of them
}