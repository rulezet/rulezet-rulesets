rule TTP_XOR_MULT_DOSStub_060e {
  strings:
    $key_060e = { 52 66 [2] 26 7e [2] 61 7c [2] 26 6d [2] 68 61 [2] 64 6b [2] 73 60 [2] 68 2e [2] 55 }

  condition:
    any of them
}