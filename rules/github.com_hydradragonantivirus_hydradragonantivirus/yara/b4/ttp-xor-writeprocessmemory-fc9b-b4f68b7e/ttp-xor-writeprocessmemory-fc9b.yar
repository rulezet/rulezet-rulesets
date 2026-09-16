rule TTP_XOR_WriteProcessMemory_fc9b {
  strings:
    $key_fc9b = { ab e9 [2] 99 cb [2] 9f fe [2] b1 fe [2] 8e e2 }

  condition:
    any of them
}