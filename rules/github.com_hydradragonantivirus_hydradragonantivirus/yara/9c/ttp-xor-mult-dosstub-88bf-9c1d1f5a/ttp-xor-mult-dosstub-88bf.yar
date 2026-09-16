rule TTP_XOR_MULT_DOSStub_88bf {
  strings:
    $key_88bf = { dc d7 [2] a8 cf [2] ef cd [2] a8 dc [2] e6 d0 [2] ea da [2] fd d1 [2] e6 9f [2] db }

  condition:
    any of them
}