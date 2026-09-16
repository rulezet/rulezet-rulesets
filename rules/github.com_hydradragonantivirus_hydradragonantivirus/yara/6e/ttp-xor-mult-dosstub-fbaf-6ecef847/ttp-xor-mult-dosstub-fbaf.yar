rule TTP_XOR_MULT_DOSStub_fbaf {
  strings:
    $key_fbaf = { af c7 [2] db df [2] 9c dd [2] db cc [2] 95 c0 [2] 99 ca [2] 8e c1 [2] 95 8f [2] a8 }

  condition:
    any of them
}