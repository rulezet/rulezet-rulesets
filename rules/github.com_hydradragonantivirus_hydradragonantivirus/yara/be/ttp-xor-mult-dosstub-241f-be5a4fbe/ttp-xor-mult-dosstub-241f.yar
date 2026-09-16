rule TTP_XOR_MULT_DOSStub_241f {
  strings:
    $key_241f = { 70 77 [2] 04 6f [2] 43 6d [2] 04 7c [2] 4a 70 [2] 46 7a [2] 51 71 [2] 4a 3f [2] 77 }

  condition:
    any of them
}