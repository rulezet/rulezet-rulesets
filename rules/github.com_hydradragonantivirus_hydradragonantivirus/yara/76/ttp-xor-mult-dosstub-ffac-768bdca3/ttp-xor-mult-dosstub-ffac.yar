rule TTP_XOR_MULT_DOSStub_ffac {
  strings:
    $key_ffac = { ab c4 [2] df dc [2] 98 de [2] df cf [2] 91 c3 [2] 9d c9 [2] 8a c2 [2] 91 8c [2] ac }

  condition:
    any of them
}