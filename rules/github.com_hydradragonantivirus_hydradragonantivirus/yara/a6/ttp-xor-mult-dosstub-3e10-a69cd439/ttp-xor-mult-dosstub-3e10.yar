rule TTP_XOR_MULT_DOSStub_3e10 {
  strings:
    $key_3e10 = { 6a 78 [2] 1e 60 [2] 59 62 [2] 1e 73 [2] 50 7f [2] 5c 75 [2] 4b 7e [2] 50 30 [2] 6d }

  condition:
    any of them
}