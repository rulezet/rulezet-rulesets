rule TTP_XOR_MULT_DOSStub_e3fc {
  strings:
    $key_e3fc = { b7 94 [2] c3 8c [2] 84 8e [2] c3 9f [2] 8d 93 [2] 81 99 [2] 96 92 [2] 8d dc [2] b0 }

  condition:
    any of them
}