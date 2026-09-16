rule TTP_XOR_WriteProcessMemory_ca8f {
  strings:
    $key_ca8f = { 9d fd [2] af df [2] a9 ea [2] 87 ea [2] b8 f6 }

  condition:
    any of them
}