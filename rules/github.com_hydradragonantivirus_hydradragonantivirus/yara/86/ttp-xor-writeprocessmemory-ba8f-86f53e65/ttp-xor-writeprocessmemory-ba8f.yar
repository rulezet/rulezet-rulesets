rule TTP_XOR_WriteProcessMemory_ba8f {
  strings:
    $key_ba8f = { ed fd [2] df df [2] d9 ea [2] f7 ea [2] c8 f6 }

  condition:
    any of them
}