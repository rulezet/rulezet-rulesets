rule TTP_XOR_MULT_DOSStub_d3e3 {
  strings:
    $key_d3e3 = { 87 8b [2] f3 93 [2] b4 91 [2] f3 80 [2] bd 8c [2] b1 86 [2] a6 8d [2] bd c3 [2] 80 }

  condition:
    any of them
}