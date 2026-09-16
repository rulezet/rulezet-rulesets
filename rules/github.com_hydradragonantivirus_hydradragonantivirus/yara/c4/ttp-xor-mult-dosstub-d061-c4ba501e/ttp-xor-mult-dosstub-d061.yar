rule TTP_XOR_MULT_DOSStub_d061 {
  strings:
    $key_d061 = { 84 09 [2] f0 11 [2] b7 13 [2] f0 02 [2] be 0e [2] b2 04 [2] a5 0f [2] be 41 [2] 83 }

  condition:
    any of them
}