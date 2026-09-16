rule TTP_XOR_MULT_DOSStub_e01e {
  strings:
    $key_e01e = { b4 76 [2] c0 6e [2] 87 6c [2] c0 7d [2] 8e 71 [2] 82 7b [2] 95 70 [2] 8e 3e [2] b3 }

  condition:
    any of them
}