rule TTP_XOR_WriteProcessMemory_b719 {
  strings:
    $key_b719 = { e0 6b [2] d2 49 [2] d4 7c [2] fa 7c [2] c5 60 }

  condition:
    any of them
}