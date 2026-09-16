rule TTP_XOR_MULT_DOSStub_e061 {
  strings:
    $key_e061 = { b4 09 [2] c0 11 [2] 87 13 [2] c0 02 [2] 8e 0e [2] 82 04 [2] 95 0f [2] 8e 41 [2] b3 }

  condition:
    any of them
}