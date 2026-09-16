rule TTP_XOR_WriteProcessMemory_2b8f {
  strings:
    $key_2b8f = { 7c fd [2] 4e df [2] 48 ea [2] 66 ea [2] 59 f6 }

  condition:
    any of them
}