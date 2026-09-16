rule TTP_XOR_MULT_DOSStub_c207 {
  strings:
    $key_c207 = { 96 6f [2] e2 77 [2] a5 75 [2] e2 64 [2] ac 68 [2] a0 62 [2] b7 69 [2] ac 27 [2] 91 }

  condition:
    any of them
}