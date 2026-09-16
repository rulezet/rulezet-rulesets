rule TTP_XOR_MULT_DOSStub_ae9c {
  strings:
    $key_ae9c = { fa f4 [2] 8e ec [2] c9 ee [2] 8e ff [2] c0 f3 [2] cc f9 [2] db f2 [2] c0 bc [2] fd }

  condition:
    any of them
}