rule TTP_XOR_WriteProcessMemory_a719 {
  strings:
    $key_a719 = { f0 6b [2] c2 49 [2] c4 7c [2] ea 7c [2] d5 60 }

  condition:
    any of them
}