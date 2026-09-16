rule TTP_XOR_MULT_DOSStub_82c9 {
  strings:
    $key_82c9 = { d6 a1 [2] a2 b9 [2] e5 bb [2] a2 aa [2] ec a6 [2] e0 ac [2] f7 a7 [2] ec e9 [2] d1 }

  condition:
    any of them
}