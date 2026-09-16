rule TTP_XOR_MULT_DOSStub_0a1f {
  strings:
    $key_0a1f = { 5e 77 [2] 2a 6f [2] 6d 6d [2] 2a 7c [2] 64 70 [2] 68 7a [2] 7f 71 [2] 64 3f [2] 59 }

  condition:
    any of them
}