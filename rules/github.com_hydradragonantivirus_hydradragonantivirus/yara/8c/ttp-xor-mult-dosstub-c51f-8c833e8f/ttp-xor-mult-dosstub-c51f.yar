rule TTP_XOR_MULT_DOSStub_c51f {
  strings:
    $key_c51f = { 91 77 [2] e5 6f [2] a2 6d [2] e5 7c [2] ab 70 [2] a7 7a [2] b0 71 [2] ab 3f [2] 96 }

  condition:
    any of them
}