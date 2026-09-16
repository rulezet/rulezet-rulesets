rule TTP_XOR_MULT_DOSStub_314d {
  strings:
    $key_314d = { 65 25 [2] 11 3d [2] 56 3f [2] 11 2e [2] 5f 22 [2] 53 28 [2] 44 23 [2] 5f 6d [2] 62 }

  condition:
    any of them
}