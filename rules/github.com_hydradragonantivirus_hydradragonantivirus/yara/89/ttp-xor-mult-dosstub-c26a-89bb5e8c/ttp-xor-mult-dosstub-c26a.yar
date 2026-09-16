rule TTP_XOR_MULT_DOSStub_c26a {
  strings:
    $key_c26a = { 96 02 [2] e2 1a [2] a5 18 [2] e2 09 [2] ac 05 [2] a0 0f [2] b7 04 [2] ac 4a [2] 91 }

  condition:
    any of them
}