rule TTP_XOR_MULT_DOSStub_140e {
  strings:
    $key_140e = { 40 66 [2] 34 7e [2] 73 7c [2] 34 6d [2] 7a 61 [2] 76 6b [2] 61 60 [2] 7a 2e [2] 47 }

  condition:
    any of them
}