rule TTP_XOR_MULT_DOSStub_eeb9 {
  strings:
    $key_eeb9 = { ba d1 [2] ce c9 [2] 89 cb [2] ce da [2] 80 d6 [2] 8c dc [2] 9b d7 [2] 80 99 [2] bd }

  condition:
    any of them
}