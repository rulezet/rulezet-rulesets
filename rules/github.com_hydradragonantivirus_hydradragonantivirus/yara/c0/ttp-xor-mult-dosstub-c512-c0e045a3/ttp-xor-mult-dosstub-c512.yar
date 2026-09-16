rule TTP_XOR_MULT_DOSStub_c512 {
  strings:
    $key_c512 = { 91 7a [2] e5 62 [2] a2 60 [2] e5 71 [2] ab 7d [2] a7 77 [2] b0 7c [2] ab 32 [2] 96 }

  condition:
    any of them
}