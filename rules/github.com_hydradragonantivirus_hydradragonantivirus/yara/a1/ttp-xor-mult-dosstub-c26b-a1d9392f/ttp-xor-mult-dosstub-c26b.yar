rule TTP_XOR_MULT_DOSStub_c26b {
  strings:
    $key_c26b = { 96 03 [2] e2 1b [2] a5 19 [2] e2 08 [2] ac 04 [2] a0 0e [2] b7 05 [2] ac 4b [2] 91 }

  condition:
    any of them
}