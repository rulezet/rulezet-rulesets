rule TTP_XOR_MULT_DOSStub_ef8d {
  strings:
    $key_ef8d = { bb e5 [2] cf fd [2] 88 ff [2] cf ee [2] 81 e2 [2] 8d e8 [2] 9a e3 [2] 81 ad [2] bc }

  condition:
    any of them
}