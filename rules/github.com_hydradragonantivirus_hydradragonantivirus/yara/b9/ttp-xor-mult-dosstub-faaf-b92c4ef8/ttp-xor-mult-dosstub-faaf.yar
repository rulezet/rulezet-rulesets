rule TTP_XOR_MULT_DOSStub_faaf {
  strings:
    $key_faaf = { ae c7 [2] da df [2] 9d dd [2] da cc [2] 94 c0 [2] 98 ca [2] 8f c1 [2] 94 8f [2] a9 }

  condition:
    any of them
}