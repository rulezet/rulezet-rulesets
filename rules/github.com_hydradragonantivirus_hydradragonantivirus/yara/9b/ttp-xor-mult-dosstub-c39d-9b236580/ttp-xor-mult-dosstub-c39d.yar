rule TTP_XOR_MULT_DOSStub_c39d {
  strings:
    $key_c39d = { 97 f5 [2] e3 ed [2] a4 ef [2] e3 fe [2] ad f2 [2] a1 f8 [2] b6 f3 [2] ad bd [2] 90 }

  condition:
    any of them
}