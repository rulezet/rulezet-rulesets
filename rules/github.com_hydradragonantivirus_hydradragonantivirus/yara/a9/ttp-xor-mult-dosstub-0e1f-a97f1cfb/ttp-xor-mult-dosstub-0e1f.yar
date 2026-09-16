rule TTP_XOR_MULT_DOSStub_0e1f {
  strings:
    $key_0e1f = { 5a 77 [2] 2e 6f [2] 69 6d [2] 2e 7c [2] 60 70 [2] 6c 7a [2] 7b 71 [2] 60 3f [2] 5d }

  condition:
    any of them
}