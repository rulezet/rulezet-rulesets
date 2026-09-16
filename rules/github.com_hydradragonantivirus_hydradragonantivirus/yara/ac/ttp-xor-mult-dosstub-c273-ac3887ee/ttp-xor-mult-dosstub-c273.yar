rule TTP_XOR_MULT_DOSStub_c273 {
  strings:
    $key_c273 = { 96 1b [2] e2 03 [2] a5 01 [2] e2 10 [2] ac 1c [2] a0 16 [2] b7 1d [2] ac 53 [2] 91 }

  condition:
    any of them
}