rule TTP_XOR_MULT_DOSStub_aecf {
  strings:
    $key_aecf = { fa a7 [2] 8e bf [2] c9 bd [2] 8e ac [2] c0 a0 [2] cc aa [2] db a1 [2] c0 ef [2] fd }

  condition:
    any of them
}