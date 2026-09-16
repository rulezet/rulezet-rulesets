rule TTP_XOR_MULT_DOSStub_c8d0 {
  strings:
    $key_c8d0 = { 9c b8 [2] e8 a0 [2] af a2 [2] e8 b3 [2] a6 bf [2] aa b5 [2] bd be [2] a6 f0 [2] 9b }

  condition:
    any of them
}