rule TTP_XOR_MULT_DOSStub_cda5 {
  strings:
    $key_cda5 = { 99 cd [2] ed d5 [2] aa d7 [2] ed c6 [2] a3 ca [2] af c0 [2] b8 cb [2] a3 85 [2] 9e }

  condition:
    any of them
}