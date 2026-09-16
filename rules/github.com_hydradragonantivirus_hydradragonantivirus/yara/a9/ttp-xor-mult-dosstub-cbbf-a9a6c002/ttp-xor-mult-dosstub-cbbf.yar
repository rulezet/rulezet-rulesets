rule TTP_XOR_MULT_DOSStub_cbbf {
  strings:
    $key_cbbf = { 9f d7 [2] eb cf [2] ac cd [2] eb dc [2] a5 d0 [2] a9 da [2] be d1 [2] a5 9f [2] 98 }

  condition:
    any of them
}