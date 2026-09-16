rule TTP_XOR_MULT_DOSStub_407d {
  strings:
    $key_407d = { 14 15 [2] 60 0d [2] 27 0f [2] 60 1e [2] 2e 12 [2] 22 18 [2] 35 13 [2] 2e 5d [2] 13 }

  condition:
    any of them
}