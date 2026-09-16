rule TTP_XOR_WriteProcessMemory_b319 {
  strings:
    $key_b319 = { e4 6b [2] d6 49 [2] d0 7c [2] fe 7c [2] c1 60 }

  condition:
    any of them
}