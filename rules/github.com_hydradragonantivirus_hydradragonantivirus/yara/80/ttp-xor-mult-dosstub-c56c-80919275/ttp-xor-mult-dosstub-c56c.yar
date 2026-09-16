rule TTP_XOR_MULT_DOSStub_c56c {
  strings:
    $key_c56c = { 91 04 [2] e5 1c [2] a2 1e [2] e5 0f [2] ab 03 [2] a7 09 [2] b0 02 [2] ab 4c [2] 96 }

  condition:
    any of them
}