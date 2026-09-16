rule TTP_XOR_MULT_DOSStub_053d {
  strings:
    $key_053d = { 51 55 [2] 25 4d [2] 62 4f [2] 25 5e [2] 6b 52 [2] 67 58 [2] 70 53 [2] 6b 1d [2] 56 }

  condition:
    any of them
}