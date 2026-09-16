rule TTP_XOR_MULT_DOSStub_c20e {
  strings:
    $key_c20e = { 96 66 [2] e2 7e [2] a5 7c [2] e2 6d [2] ac 61 [2] a0 6b [2] b7 60 [2] ac 2e [2] 91 }

  condition:
    any of them
}