rule TTP_XOR_MULT_DOSStub_dc9d {
  strings:
    $key_dc9d = { 88 f5 [2] fc ed [2] bb ef [2] fc fe [2] b2 f2 [2] be f8 [2] a9 f3 [2] b2 bd [2] 8f }

  condition:
    any of them
}