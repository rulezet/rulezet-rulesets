rule TTP_XOR_MULT_DOSStub_e81e {
  strings:
    $key_e81e = { bc 76 [2] c8 6e [2] 8f 6c [2] c8 7d [2] 86 71 [2] 8a 7b [2] 9d 70 [2] 86 3e [2] bb }

  condition:
    any of them
}