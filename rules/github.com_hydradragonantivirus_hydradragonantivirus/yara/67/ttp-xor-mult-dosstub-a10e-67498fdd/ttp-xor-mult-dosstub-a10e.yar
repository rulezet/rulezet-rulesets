rule TTP_XOR_MULT_DOSStub_a10e {
  strings:
    $key_a10e = { f5 66 [2] 81 7e [2] c6 7c [2] 81 6d [2] cf 61 [2] c3 6b [2] d4 60 [2] cf 2e [2] f2 }

  condition:
    any of them
}