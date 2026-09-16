rule TTP_XOR_MULT_DOSStub_d32a {
  strings:
    $key_d32a = { 87 42 [2] f3 5a [2] b4 58 [2] f3 49 [2] bd 45 [2] b1 4f [2] a6 44 [2] bd 0a [2] 80 }

  condition:
    any of them
}