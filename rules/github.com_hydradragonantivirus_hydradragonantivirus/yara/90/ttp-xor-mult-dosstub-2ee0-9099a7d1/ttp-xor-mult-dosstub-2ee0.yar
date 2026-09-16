rule TTP_XOR_MULT_DOSStub_2ee0 {
  strings:
    $key_2ee0 = { 7a 88 [2] 0e 90 [2] 49 92 [2] 0e 83 [2] 40 8f [2] 4c 85 [2] 5b 8e [2] 40 c0 [2] 7d }

  condition:
    any of them
}