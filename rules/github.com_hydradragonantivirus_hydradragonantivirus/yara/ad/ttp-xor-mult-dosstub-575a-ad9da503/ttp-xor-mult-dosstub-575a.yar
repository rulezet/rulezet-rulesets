rule TTP_XOR_MULT_DOSStub_575a {
  strings:
    $key_575a = { 03 32 [2] 77 2a [2] 30 28 [2] 77 39 [2] 39 35 [2] 35 3f [2] 22 34 [2] 39 7a [2] 04 }

  condition:
    any of them
}