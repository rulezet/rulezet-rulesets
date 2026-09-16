rule TTP_XOR_MULT_DOSStub_c575 {
  strings:
    $key_c575 = { 91 1d [2] e5 05 [2] a2 07 [2] e5 16 [2] ab 1a [2] a7 10 [2] b0 1b [2] ab 55 [2] 96 }

  condition:
    any of them
}