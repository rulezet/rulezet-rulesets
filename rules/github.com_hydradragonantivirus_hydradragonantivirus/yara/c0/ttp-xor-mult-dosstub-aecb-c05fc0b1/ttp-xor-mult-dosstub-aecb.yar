rule TTP_XOR_MULT_DOSStub_aecb {
  strings:
    $key_aecb = { fa a3 [2] 8e bb [2] c9 b9 [2] 8e a8 [2] c0 a4 [2] cc ae [2] db a5 [2] c0 eb [2] fd }

  condition:
    any of them
}