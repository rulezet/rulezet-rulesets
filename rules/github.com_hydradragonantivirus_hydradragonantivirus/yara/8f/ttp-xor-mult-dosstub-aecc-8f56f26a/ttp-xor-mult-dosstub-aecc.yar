rule TTP_XOR_MULT_DOSStub_aecc {
  strings:
    $key_aecc = { fa a4 [2] 8e bc [2] c9 be [2] 8e af [2] c0 a3 [2] cc a9 [2] db a2 [2] c0 ec [2] fd }

  condition:
    any of them
}