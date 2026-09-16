rule TTP_XOR_MULT_DOSStub_a4ed {
  strings:
    $key_a4ed = { f0 85 [2] 84 9d [2] c3 9f [2] 84 8e [2] ca 82 [2] c6 88 [2] d1 83 [2] ca cd [2] f7 }

  condition:
    any of them
}