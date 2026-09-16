rule TTP_XOR_MULT_DOSStub_341f {
  strings:
    $key_341f = { 60 77 [2] 14 6f [2] 53 6d [2] 14 7c [2] 5a 70 [2] 56 7a [2] 41 71 [2] 5a 3f [2] 67 }

  condition:
    any of them
}