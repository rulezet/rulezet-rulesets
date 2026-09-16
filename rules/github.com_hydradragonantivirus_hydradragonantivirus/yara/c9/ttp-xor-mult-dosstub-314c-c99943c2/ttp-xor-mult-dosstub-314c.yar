rule TTP_XOR_MULT_DOSStub_314c {
  strings:
    $key_314c = { 65 24 [2] 11 3c [2] 56 3e [2] 11 2f [2] 5f 23 [2] 53 29 [2] 44 22 [2] 5f 6c [2] 62 }

  condition:
    any of them
}