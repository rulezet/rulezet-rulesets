rule TTP_XOR_MULT_DOSStub_a46c {
  strings:
    $key_a46c = { f0 04 [2] 84 1c [2] c3 1e [2] 84 0f [2] ca 03 [2] c6 09 [2] d1 02 [2] ca 4c [2] f7 }

  condition:
    any of them
}