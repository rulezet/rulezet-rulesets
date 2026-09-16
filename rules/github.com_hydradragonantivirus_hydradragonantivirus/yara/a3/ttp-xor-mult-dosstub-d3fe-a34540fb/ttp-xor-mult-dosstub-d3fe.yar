rule TTP_XOR_MULT_DOSStub_d3fe {
  strings:
    $key_d3fe = { 87 96 [2] f3 8e [2] b4 8c [2] f3 9d [2] bd 91 [2] b1 9b [2] a6 90 [2] bd de [2] 80 }

  condition:
    any of them
}