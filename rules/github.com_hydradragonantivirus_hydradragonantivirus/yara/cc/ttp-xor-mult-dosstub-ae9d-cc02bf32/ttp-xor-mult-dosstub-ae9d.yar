rule TTP_XOR_MULT_DOSStub_ae9d {
  strings:
    $key_ae9d = { fa f5 [2] 8e ed [2] c9 ef [2] 8e fe [2] c0 f2 [2] cc f8 [2] db f3 [2] c0 bd [2] fd }

  condition:
    any of them
}