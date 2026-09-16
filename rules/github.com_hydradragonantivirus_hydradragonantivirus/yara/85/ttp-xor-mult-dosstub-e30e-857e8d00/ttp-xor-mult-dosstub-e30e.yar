rule TTP_XOR_MULT_DOSStub_e30e {
  strings:
    $key_e30e = { b7 66 [2] c3 7e [2] 84 7c [2] c3 6d [2] 8d 61 [2] 81 6b [2] 96 60 [2] 8d 2e [2] b0 }

  condition:
    any of them
}