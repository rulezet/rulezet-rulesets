rule TTP_XOR_WriteProcessMemory_f88f {
  strings:
    $key_f88f = { af fd [2] 9d df [2] 9b ea [2] b5 ea [2] 8a f6 }

  condition:
    any of them
}