rule TTP_XOR_MULT_DOSStub_e66c {
  strings:
    $key_e66c = { b2 04 [2] c6 1c [2] 81 1e [2] c6 0f [2] 88 03 [2] 84 09 [2] 93 02 [2] 88 4c [2] b5 }

  condition:
    any of them
}