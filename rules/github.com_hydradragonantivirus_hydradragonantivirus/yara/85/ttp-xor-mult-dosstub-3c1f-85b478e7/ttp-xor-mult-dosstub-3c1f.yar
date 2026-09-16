rule TTP_XOR_MULT_DOSStub_3c1f {
  strings:
    $key_3c1f = { 68 77 [2] 1c 6f [2] 5b 6d [2] 1c 7c [2] 52 70 [2] 5e 7a [2] 49 71 [2] 52 3f [2] 6f }

  condition:
    any of them
}