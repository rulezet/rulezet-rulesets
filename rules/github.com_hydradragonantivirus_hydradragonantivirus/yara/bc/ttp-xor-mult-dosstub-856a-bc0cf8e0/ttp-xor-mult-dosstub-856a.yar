rule TTP_XOR_MULT_DOSStub_856a {
  strings:
    $key_856a = { d1 02 [2] a5 1a [2] e2 18 [2] a5 09 [2] eb 05 [2] e7 0f [2] f0 04 [2] eb 4a [2] d6 }

  condition:
    any of them
}