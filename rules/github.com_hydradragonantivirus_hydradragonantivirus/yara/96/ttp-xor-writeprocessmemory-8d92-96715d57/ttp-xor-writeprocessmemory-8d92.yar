rule TTP_XOR_WriteProcessMemory_8d92 {
  strings:
    $key_8d92 = { da e0 [2] e8 c2 [2] ee f7 [2] c0 f7 [2] ff eb }

  condition:
    any of them
}