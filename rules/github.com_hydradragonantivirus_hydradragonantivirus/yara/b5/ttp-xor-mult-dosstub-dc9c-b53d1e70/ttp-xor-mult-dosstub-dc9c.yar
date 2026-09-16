rule TTP_XOR_MULT_DOSStub_dc9c {
  strings:
    $key_dc9c = { 88 f4 [2] fc ec [2] bb ee [2] fc ff [2] b2 f3 [2] be f9 [2] a9 f2 [2] b2 bc [2] 8f }

  condition:
    any of them
}