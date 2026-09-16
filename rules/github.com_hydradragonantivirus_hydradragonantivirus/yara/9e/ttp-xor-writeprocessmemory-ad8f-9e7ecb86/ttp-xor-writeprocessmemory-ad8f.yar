rule TTP_XOR_WriteProcessMemory_ad8f {
  strings:
    $key_ad8f = { fa fd [2] c8 df [2] ce ea [2] e0 ea [2] df f6 }

  condition:
    any of them
}