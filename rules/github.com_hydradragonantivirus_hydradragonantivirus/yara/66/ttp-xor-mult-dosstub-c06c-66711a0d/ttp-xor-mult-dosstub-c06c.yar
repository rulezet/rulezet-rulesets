rule TTP_XOR_MULT_DOSStub_c06c {
  strings:
    $key_c06c = { 94 04 [2] e0 1c [2] a7 1e [2] e0 0f [2] ae 03 [2] a2 09 [2] b5 02 [2] ae 4c [2] 93 }

  condition:
    any of them
}