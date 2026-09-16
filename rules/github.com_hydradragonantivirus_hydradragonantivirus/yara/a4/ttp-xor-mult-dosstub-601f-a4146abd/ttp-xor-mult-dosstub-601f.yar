rule TTP_XOR_MULT_DOSStub_601f {
  strings:
    $key_601f = { 34 77 [2] 40 6f [2] 07 6d [2] 40 7c [2] 0e 70 [2] 02 7a [2] 15 71 [2] 0e 3f [2] 33 }

  condition:
    any of them
}