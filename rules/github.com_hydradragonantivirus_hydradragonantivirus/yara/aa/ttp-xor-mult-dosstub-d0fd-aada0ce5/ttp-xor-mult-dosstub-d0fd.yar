rule TTP_XOR_MULT_DOSStub_d0fd {
  strings:
    $key_d0fd = { 84 95 [2] f0 8d [2] b7 8f [2] f0 9e [2] be 92 [2] b2 98 [2] a5 93 [2] be dd [2] 83 }

  condition:
    any of them
}