rule TTP_XOR_MULT_DOSStub_657b {
  strings:
    $key_657b = { 31 13 [2] 45 0b [2] 02 09 [2] 45 18 [2] 0b 14 [2] 07 1e [2] 10 15 [2] 0b 5b [2] 36 }

  condition:
    any of them
}