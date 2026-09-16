rule TTP_XOR_MULT_DOSStub_373d {
  strings:
    $key_373d = { 63 55 [2] 17 4d [2] 50 4f [2] 17 5e [2] 59 52 [2] 55 58 [2] 42 53 [2] 59 1d [2] 64 }

  condition:
    any of them
}