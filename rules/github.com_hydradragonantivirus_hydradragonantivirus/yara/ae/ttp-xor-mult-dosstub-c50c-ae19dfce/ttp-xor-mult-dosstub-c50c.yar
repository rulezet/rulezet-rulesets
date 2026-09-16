rule TTP_XOR_MULT_DOSStub_c50c {
  strings:
    $key_c50c = { 91 64 [2] e5 7c [2] a2 7e [2] e5 6f [2] ab 63 [2] a7 69 [2] b0 62 [2] ab 2c [2] 96 }

  condition:
    any of them
}