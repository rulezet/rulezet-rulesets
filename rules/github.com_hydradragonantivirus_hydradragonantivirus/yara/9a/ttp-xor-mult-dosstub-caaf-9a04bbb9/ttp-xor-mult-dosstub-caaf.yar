rule TTP_XOR_MULT_DOSStub_caaf {
  strings:
    $key_caaf = { 9e c7 [2] ea df [2] ad dd [2] ea cc [2] a4 c0 [2] a8 ca [2] bf c1 [2] a4 8f [2] 99 }

  condition:
    any of them
}