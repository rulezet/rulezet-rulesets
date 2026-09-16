rule TTP_XOR_MULT_DOSStub_021f {
  strings:
    $key_021f = { 56 77 [2] 22 6f [2] 65 6d [2] 22 7c [2] 6c 70 [2] 60 7a [2] 77 71 [2] 6c 3f [2] 51 }

  condition:
    any of them
}