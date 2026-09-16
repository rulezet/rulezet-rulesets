rule TTP_XOR_MULT_DOSStub_cddd {
  strings:
    $key_cddd = { 99 b5 [2] ed ad [2] aa af [2] ed be [2] a3 b2 [2] af b8 [2] b8 b3 [2] a3 fd [2] 9e }

  condition:
    any of them
}