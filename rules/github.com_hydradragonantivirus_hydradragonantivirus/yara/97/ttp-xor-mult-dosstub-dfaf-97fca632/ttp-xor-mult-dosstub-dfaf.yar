rule TTP_XOR_MULT_DOSStub_dfaf {
  strings:
    $key_dfaf = { 8b c7 [2] ff df [2] b8 dd [2] ff cc [2] b1 c0 [2] bd ca [2] aa c1 [2] b1 8f [2] 8c }

  condition:
    any of them
}