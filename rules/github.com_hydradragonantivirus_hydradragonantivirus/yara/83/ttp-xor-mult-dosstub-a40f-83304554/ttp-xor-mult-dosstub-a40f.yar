rule TTP_XOR_MULT_DOSStub_a40f {
  strings:
    $key_a40f = { f0 67 [2] 84 7f [2] c3 7d [2] 84 6c [2] ca 60 [2] c6 6a [2] d1 61 [2] ca 2f [2] f7 }

  condition:
    any of them
}