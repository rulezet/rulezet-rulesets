rule TTP_XOR_MULT_DOSStub_d86a {
  strings:
    $key_d86a = { 8c 02 [2] f8 1a [2] bf 18 [2] f8 09 [2] b6 05 [2] ba 0f [2] ad 04 [2] b6 4a [2] 8b }

  condition:
    any of them
}