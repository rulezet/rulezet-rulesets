rule TTP_XOR_MULT_DOSStub_e5fe {
  strings:
    $key_e5fe = { b1 96 [2] c5 8e [2] 82 8c [2] c5 9d [2] 8b 91 [2] 87 9b [2] 90 90 [2] 8b de [2] b6 }

  condition:
    any of them
}