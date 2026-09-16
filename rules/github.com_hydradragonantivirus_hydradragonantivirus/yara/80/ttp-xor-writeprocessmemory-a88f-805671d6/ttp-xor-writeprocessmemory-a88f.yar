rule TTP_XOR_WriteProcessMemory_a88f {
  strings:
    $key_a88f = { ff fd [2] cd df [2] cb ea [2] e5 ea [2] da f6 }

  condition:
    any of them
}