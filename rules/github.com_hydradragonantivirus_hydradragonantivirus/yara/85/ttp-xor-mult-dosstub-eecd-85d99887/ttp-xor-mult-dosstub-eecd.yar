rule TTP_XOR_MULT_DOSStub_eecd {
  strings:
    $key_eecd = { ba a5 [2] ce bd [2] 89 bf [2] ce ae [2] 80 a2 [2] 8c a8 [2] 9b a3 [2] 80 ed [2] bd }

  condition:
    any of them
}