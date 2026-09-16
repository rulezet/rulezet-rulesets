rule TTP_XOR_MULT_DOSStub_bda5 {
  strings:
    $key_bda5 = { e9 cd [2] 9d d5 [2] da d7 [2] 9d c6 [2] d3 ca [2] df c0 [2] c8 cb [2] d3 85 [2] ee }

  condition:
    any of them
}