rule TTP_XOR_MULT_DOSStub_301f {
  strings:
    $key_301f = { 64 77 [2] 10 6f [2] 57 6d [2] 10 7c [2] 5e 70 [2] 52 7a [2] 45 71 [2] 5e 3f [2] 63 }

  condition:
    any of them
}