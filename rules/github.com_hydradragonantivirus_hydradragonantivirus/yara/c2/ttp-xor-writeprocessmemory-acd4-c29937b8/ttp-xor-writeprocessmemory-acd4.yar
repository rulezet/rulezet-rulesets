rule TTP_XOR_WriteProcessMemory_acd4 {
  strings:
    $key_acd4 = { fb a6 [2] c9 84 [2] cf b1 [2] e1 b1 [2] de ad }

  condition:
    any of them
}