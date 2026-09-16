rule TTP_XOR_MULT_DOSStub_311e {
  strings:
    $key_311e = { 65 76 [2] 11 6e [2] 56 6c [2] 11 7d [2] 5f 71 [2] 53 7b [2] 44 70 [2] 5f 3e [2] 62 }

  condition:
    any of them
}