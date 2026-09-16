rule TTP_XOR_MULT_DOSStub_cdcd {
  strings:
    $key_cdcd = { 99 a5 [2] ed bd [2] aa bf [2] ed ae [2] a3 a2 [2] af a8 [2] b8 a3 [2] a3 ed [2] 9e }

  condition:
    any of them
}