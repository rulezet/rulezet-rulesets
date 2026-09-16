rule TTP_XOR_MULT_DOSStub_8fcc {
  strings:
    $key_8fcc = { db a4 [2] af bc [2] e8 be [2] af af [2] e1 a3 [2] ed a9 [2] fa a2 [2] e1 ec [2] dc }

  condition:
    any of them
}