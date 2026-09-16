rule TTP_XOR_MULT_DOSStub_d40f {
  strings:
    $key_d40f = { 80 67 [2] f4 7f [2] b3 7d [2] f4 6c [2] ba 60 [2] b6 6a [2] a1 61 [2] ba 2f [2] 87 }

  condition:
    any of them
}