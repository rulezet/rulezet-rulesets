rule TTP_XOR_WriteProcessMemory_ba98 {
  strings:
    $key_ba98 = { ed ea [2] df c8 [2] d9 fd [2] f7 fd [2] c8 e1 }

  condition:
    any of them
}