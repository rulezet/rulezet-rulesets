rule TTP_XOR_MULT_DOSStub_077f {
  strings:
    $key_077f = { 53 17 [2] 27 0f [2] 60 0d [2] 27 1c [2] 69 10 [2] 65 1a [2] 72 11 [2] 69 5f [2] 54 }

  condition:
    any of them
}