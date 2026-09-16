rule TTP_XOR_MULT_DOSStub_133d {
  strings:
    $key_133d = { 47 55 [2] 33 4d [2] 74 4f [2] 33 5e [2] 7d 52 [2] 71 58 [2] 66 53 [2] 7d 1d [2] 40 }

  condition:
    any of them
}