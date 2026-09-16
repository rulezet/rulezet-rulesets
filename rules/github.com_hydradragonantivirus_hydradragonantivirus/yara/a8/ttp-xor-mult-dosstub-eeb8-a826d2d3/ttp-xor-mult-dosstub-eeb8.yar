rule TTP_XOR_MULT_DOSStub_eeb8 {
  strings:
    $key_eeb8 = { ba d0 [2] ce c8 [2] 89 ca [2] ce db [2] 80 d7 [2] 8c dd [2] 9b d6 [2] 80 98 [2] bd }

  condition:
    any of them
}