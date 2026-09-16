rule TTP_XOR_MULT_DOSStub_3e37 {
  strings:
    $key_3e37 = { 6a 5f [2] 1e 47 [2] 59 45 [2] 1e 54 [2] 50 58 [2] 5c 52 [2] 4b 59 [2] 50 17 [2] 6d }

  condition:
    any of them
}