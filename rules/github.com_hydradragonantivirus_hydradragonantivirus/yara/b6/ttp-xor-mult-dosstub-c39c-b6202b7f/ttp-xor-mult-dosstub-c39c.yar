rule TTP_XOR_MULT_DOSStub_c39c {
  strings:
    $key_c39c = { 97 f4 [2] e3 ec [2] a4 ee [2] e3 ff [2] ad f3 [2] a1 f9 [2] b6 f2 [2] ad bc [2] 90 }

  condition:
    any of them
}