rule TTP_XOR_MULT_DOSStub_3ef0 {
  strings:
    $key_3ef0 = { 6a 98 [2] 1e 80 [2] 59 82 [2] 1e 93 [2] 50 9f [2] 5c 95 [2] 4b 9e [2] 50 d0 [2] 6d }

  condition:
    any of them
}