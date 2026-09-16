rule TTP_XOR_MULT_DOSStub_110e {
  strings:
    $key_110e = { 45 66 [2] 31 7e [2] 76 7c [2] 31 6d [2] 7f 61 [2] 73 6b [2] 64 60 [2] 7f 2e [2] 42 }

  condition:
    any of them
}