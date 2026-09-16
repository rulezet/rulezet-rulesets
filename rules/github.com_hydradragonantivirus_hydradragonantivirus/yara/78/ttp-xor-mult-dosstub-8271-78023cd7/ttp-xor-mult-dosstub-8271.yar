rule TTP_XOR_MULT_DOSStub_8271 {
  strings:
    $key_8271 = { d6 19 [2] a2 01 [2] e5 03 [2] a2 12 [2] ec 1e [2] e0 14 [2] f7 1f [2] ec 51 [2] d1 }

  condition:
    any of them
}