rule TTP_XOR_MULT_DOSStub_343d {
  strings:
    $key_343d = { 60 55 [2] 14 4d [2] 53 4f [2] 14 5e [2] 5a 52 [2] 56 58 [2] 41 53 [2] 5a 1d [2] 67 }

  condition:
    any of them
}