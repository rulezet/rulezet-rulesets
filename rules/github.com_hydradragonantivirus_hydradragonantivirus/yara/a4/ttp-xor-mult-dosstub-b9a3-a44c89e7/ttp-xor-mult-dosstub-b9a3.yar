rule TTP_XOR_MULT_DOSStub_b9a3 {
  strings:
    $key_b9a3 = { ed cb [2] 99 d3 [2] de d1 [2] 99 c0 [2] d7 cc [2] db c6 [2] cc cd [2] d7 83 [2] ea }

  condition:
    any of them
}