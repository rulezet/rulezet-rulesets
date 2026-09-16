rule TTP_XOR_MULT_DOSStub_d36f {
  strings:
    $key_d36f = { 87 07 [2] f3 1f [2] b4 1d [2] f3 0c [2] bd 00 [2] b1 0a [2] a6 01 [2] bd 4f [2] 80 }

  condition:
    any of them
}