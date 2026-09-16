rule TTP_XOR_WriteProcessMemory_a718 {
  strings:
    $key_a718 = { f0 6a [2] c2 48 [2] c4 7d [2] ea 7d [2] d5 61 }

  condition:
    any of them
}