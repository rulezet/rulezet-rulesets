rule TTP_XOR_MULT_DOSStub_0a3e {
  strings:
    $key_0a3e = { 5e 56 [2] 2a 4e [2] 6d 4c [2] 2a 5d [2] 64 51 [2] 68 5b [2] 7f 50 [2] 64 1e [2] 59 }

  condition:
    any of them
}