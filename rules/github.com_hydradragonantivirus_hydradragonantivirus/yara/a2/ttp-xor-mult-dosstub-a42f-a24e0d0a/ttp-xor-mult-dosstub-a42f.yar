rule TTP_XOR_MULT_DOSStub_a42f {
  strings:
    $key_a42f = { f0 47 [2] 84 5f [2] c3 5d [2] 84 4c [2] ca 40 [2] c6 4a [2] d1 41 [2] ca 0f [2] f7 }

  condition:
    any of them
}