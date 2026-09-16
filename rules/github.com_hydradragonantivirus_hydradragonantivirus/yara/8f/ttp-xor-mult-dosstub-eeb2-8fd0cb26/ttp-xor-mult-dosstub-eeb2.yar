rule TTP_XOR_MULT_DOSStub_eeb2 {
  strings:
    $key_eeb2 = { ba da [2] ce c2 [2] 89 c0 [2] ce d1 [2] 80 dd [2] 8c d7 [2] 9b dc [2] 80 92 [2] bd }

  condition:
    any of them
}