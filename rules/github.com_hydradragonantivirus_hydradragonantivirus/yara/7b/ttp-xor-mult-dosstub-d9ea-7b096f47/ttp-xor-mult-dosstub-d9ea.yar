rule TTP_XOR_MULT_DOSStub_d9ea {
  strings:
    $key_d9ea = { 8d 82 [2] f9 9a [2] be 98 [2] f9 89 [2] b7 85 [2] bb 8f [2] ac 84 [2] b7 ca [2] 8a }

  condition:
    any of them
}