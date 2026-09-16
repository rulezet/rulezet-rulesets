rule TTP_XOR_MULT_DOSStub_c50b {
  strings:
    $key_c50b = { 91 63 [2] e5 7b [2] a2 79 [2] e5 68 [2] ab 64 [2] a7 6e [2] b0 65 [2] ab 2b [2] 96 }

  condition:
    any of them
}