rule TTP_XOR_MULT_DOSStub_441f {
  strings:
    $key_441f = { 10 77 [2] 64 6f [2] 23 6d [2] 64 7c [2] 2a 70 [2] 26 7a [2] 31 71 [2] 2a 3f [2] 17 }

  condition:
    any of them
}