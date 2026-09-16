rule TTP_XOR_WriteProcessMemory_ffba {
  strings:
    $key_ffba = { a8 c8 [2] 9a ea [2] 9c df [2] b2 df [2] 8d c3 }

  condition:
    any of them
}