rule TTP_XOR_MULT_DOSStub_dca5 {
  strings:
    $key_dca5 = { 88 cd [2] fc d5 [2] bb d7 [2] fc c6 [2] b2 ca [2] be c0 [2] a9 cb [2] b2 85 [2] 8f }

  condition:
    any of them
}