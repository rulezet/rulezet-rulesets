rule TTP_XOR_MULT_DOSStub_2e1f {
  strings:
    $key_2e1f = { 7a 77 [2] 0e 6f [2] 49 6d [2] 0e 7c [2] 40 70 [2] 4c 7a [2] 5b 71 [2] 40 3f [2] 7d }

  condition:
    any of them
}