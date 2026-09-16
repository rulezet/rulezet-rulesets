rule TTP_XOR_MULT_DOSStub_d6ea {
  strings:
    $key_d6ea = { 82 82 [2] f6 9a [2] b1 98 [2] f6 89 [2] b8 85 [2] b4 8f [2] a3 84 [2] b8 ca [2] 85 }

  condition:
    any of them
}