rule TTP_XOR_MULT_DOSStub_113e {
  strings:
    $key_113e = { 45 56 [2] 31 4e [2] 76 4c [2] 31 5d [2] 7f 51 [2] 73 5b [2] 64 50 [2] 7f 1e [2] 42 }

  condition:
    any of them
}