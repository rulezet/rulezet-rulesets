rule TTP_XOR_MULT_DOSStub_c4fe {
  strings:
    $key_c4fe = { 90 96 [2] e4 8e [2] a3 8c [2] e4 9d [2] aa 91 [2] a6 9b [2] b1 90 [2] aa de [2] 97 }

  condition:
    any of them
}