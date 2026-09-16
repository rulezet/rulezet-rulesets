rule TTP_XOR_MULT_DOSStub_39e0 {
  strings:
    $key_39e0 = { 6d 88 [2] 19 90 [2] 5e 92 [2] 19 83 [2] 57 8f [2] 5b 85 [2] 4c 8e [2] 57 c0 [2] 6a }

  condition:
    any of them
}