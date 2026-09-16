rule TTP_XOR_MULT_DOSStub_314a {
  strings:
    $key_314a = { 65 22 [2] 11 3a [2] 56 38 [2] 11 29 [2] 5f 25 [2] 53 2f [2] 44 24 [2] 5f 6a [2] 62 }

  condition:
    any of them
}