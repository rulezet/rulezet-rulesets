rule TTP_XOR_WriteProcessMemory_088f {
  strings:
    $key_088f = { 5f fd [2] 6d df [2] 6b ea [2] 45 ea [2] 7a f6 }

  condition:
    any of them
}