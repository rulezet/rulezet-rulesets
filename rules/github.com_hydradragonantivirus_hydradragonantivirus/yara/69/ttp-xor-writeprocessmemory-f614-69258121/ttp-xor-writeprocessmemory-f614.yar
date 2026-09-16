rule TTP_XOR_WriteProcessMemory_f614 {
  strings:
    $key_f614 = { a1 66 [2] 93 44 [2] 95 71 [2] bb 71 [2] 84 6d }

  condition:
    any of them
}