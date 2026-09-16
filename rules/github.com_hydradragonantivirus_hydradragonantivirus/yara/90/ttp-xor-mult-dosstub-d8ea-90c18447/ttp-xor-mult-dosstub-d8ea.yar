rule TTP_XOR_MULT_DOSStub_d8ea {
  strings:
    $key_d8ea = { 8c 82 [2] f8 9a [2] bf 98 [2] f8 89 [2] b6 85 [2] ba 8f [2] ad 84 [2] b6 ca [2] 8b }

  condition:
    any of them
}