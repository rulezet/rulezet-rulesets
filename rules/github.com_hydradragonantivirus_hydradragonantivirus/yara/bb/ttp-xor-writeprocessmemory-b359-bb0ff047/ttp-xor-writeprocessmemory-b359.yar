rule TTP_XOR_WriteProcessMemory_b359 {
  strings:
    $key_b359 = { e4 2b [2] d6 09 [2] d0 3c [2] fe 3c [2] c1 20 }

  condition:
    any of them
}