rule TTP_XOR_MULT_DOSStub_ff8d {
  strings:
    $key_ff8d = { ab e5 [2] df fd [2] 98 ff [2] df ee [2] 91 e2 [2] 9d e8 [2] 8a e3 [2] 91 ad [2] ac }

  condition:
    any of them
}