rule TTP_XOR_MULT_DOSStub_29ce {
  strings:
    $key_29ce = { 7d a6 [2] 09 be [2] 4e bc [2] 09 ad [2] 47 a1 [2] 4b ab [2] 5c a0 [2] 47 ee [2] 7a }

  condition:
    any of them
}