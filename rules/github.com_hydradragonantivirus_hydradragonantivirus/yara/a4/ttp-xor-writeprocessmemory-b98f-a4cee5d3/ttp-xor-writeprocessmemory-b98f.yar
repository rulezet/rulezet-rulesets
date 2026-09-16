rule TTP_XOR_WriteProcessMemory_b98f {
  strings:
    $key_b98f = { ee fd [2] dc df [2] da ea [2] f4 ea [2] cb f6 }

  condition:
    any of them
}