rule TTP_XOR_MULT_DOSStub_514c {
  strings:
    $key_514c = { 05 24 [2] 71 3c [2] 36 3e [2] 71 2f [2] 3f 23 [2] 33 29 [2] 24 22 [2] 3f 6c [2] 02 }

  condition:
    any of them
}