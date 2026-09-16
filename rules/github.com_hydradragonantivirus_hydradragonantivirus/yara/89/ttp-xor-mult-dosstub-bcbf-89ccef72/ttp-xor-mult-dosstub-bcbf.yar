rule TTP_XOR_MULT_DOSStub_bcbf {
  strings:
    $key_bcbf = { e8 d7 [2] 9c cf [2] db cd [2] 9c dc [2] d2 d0 [2] de da [2] c9 d1 [2] d2 9f [2] ef }

  condition:
    any of them
}