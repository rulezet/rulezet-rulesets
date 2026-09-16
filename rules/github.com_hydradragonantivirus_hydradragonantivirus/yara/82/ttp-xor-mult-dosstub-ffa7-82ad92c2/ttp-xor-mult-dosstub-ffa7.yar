rule TTP_XOR_MULT_DOSStub_ffa7 {
  strings:
    $key_ffa7 = { ab cf [2] df d7 [2] 98 d5 [2] df c4 [2] 91 c8 [2] 9d c2 [2] 8a c9 [2] 91 87 [2] ac }

  condition:
    any of them
}