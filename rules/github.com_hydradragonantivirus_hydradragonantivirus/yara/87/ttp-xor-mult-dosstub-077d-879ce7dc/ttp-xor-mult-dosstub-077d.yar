rule TTP_XOR_MULT_DOSStub_077d {
  strings:
    $key_077d = { 53 15 [2] 27 0d [2] 60 0f [2] 27 1e [2] 69 12 [2] 65 18 [2] 72 13 [2] 69 5d [2] 54 }

  condition:
    any of them
}