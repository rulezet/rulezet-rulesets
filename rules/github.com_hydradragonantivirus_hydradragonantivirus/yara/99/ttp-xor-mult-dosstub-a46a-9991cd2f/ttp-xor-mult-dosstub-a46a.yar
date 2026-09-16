rule TTP_XOR_MULT_DOSStub_a46a {
  strings:
    $key_a46a = { f0 02 [2] 84 1a [2] c3 18 [2] 84 09 [2] ca 05 [2] c6 0f [2] d1 04 [2] ca 4a [2] f7 }

  condition:
    any of them
}