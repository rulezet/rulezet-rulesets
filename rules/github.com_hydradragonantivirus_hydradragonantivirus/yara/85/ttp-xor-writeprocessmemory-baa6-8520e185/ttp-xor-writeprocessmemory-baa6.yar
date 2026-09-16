rule TTP_XOR_WriteProcessMemory_baa6 {
  strings:
    $key_baa6 = { ed d4 [2] df f6 [2] d9 c3 [2] f7 c3 [2] c8 df }

  condition:
    any of them
}