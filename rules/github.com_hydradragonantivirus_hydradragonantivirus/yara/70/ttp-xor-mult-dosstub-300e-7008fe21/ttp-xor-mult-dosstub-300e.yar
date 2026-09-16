rule TTP_XOR_MULT_DOSStub_300e {
  strings:
    $key_300e = { 64 66 [2] 10 7e [2] 57 7c [2] 10 6d [2] 5e 61 [2] 52 6b [2] 45 60 [2] 5e 2e [2] 63 }

  condition:
    any of them
}