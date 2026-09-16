rule TTP_XOR_MULT_DOSStub_3e00 {
  strings:
    $key_3e00 = { 6a 68 [2] 1e 70 [2] 59 72 [2] 1e 63 [2] 50 6f [2] 5c 65 [2] 4b 6e [2] 50 20 [2] 6d }

  condition:
    any of them
}