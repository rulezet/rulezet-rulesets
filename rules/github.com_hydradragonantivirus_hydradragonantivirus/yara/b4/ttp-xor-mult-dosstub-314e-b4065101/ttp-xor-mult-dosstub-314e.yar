rule TTP_XOR_MULT_DOSStub_314e {
  strings:
    $key_314e = { 65 26 [2] 11 3e [2] 56 3c [2] 11 2d [2] 5f 21 [2] 53 2b [2] 44 20 [2] 5f 6e [2] 62 }

  condition:
    any of them
}