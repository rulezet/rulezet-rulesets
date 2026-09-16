rule TTP_XOR_MULT_DOSStub_c22b {
  strings:
    $key_c22b = { 96 43 [2] e2 5b [2] a5 59 [2] e2 48 [2] ac 44 [2] a0 4e [2] b7 45 [2] ac 0b [2] 91 }

  condition:
    any of them
}