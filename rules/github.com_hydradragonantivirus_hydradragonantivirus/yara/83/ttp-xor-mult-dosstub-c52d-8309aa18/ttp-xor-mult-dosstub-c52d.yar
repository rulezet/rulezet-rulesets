rule TTP_XOR_MULT_DOSStub_c52d {
  strings:
    $key_c52d = { 91 45 [2] e5 5d [2] a2 5f [2] e5 4e [2] ab 42 [2] a7 48 [2] b0 43 [2] ab 0d [2] 96 }

  condition:
    any of them
}