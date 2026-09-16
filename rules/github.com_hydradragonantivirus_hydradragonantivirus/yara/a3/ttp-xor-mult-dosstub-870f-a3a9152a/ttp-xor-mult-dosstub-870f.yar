rule TTP_XOR_MULT_DOSStub_870f {
  strings:
    $key_870f = { d3 67 [2] a7 7f [2] e0 7d [2] a7 6c [2] e9 60 [2] e5 6a [2] f2 61 [2] e9 2f [2] d4 }

  condition:
    any of them
}