rule TTP_XOR_MULT_DOSStub_cbe8 {
  strings:
    $key_cbe8 = { 9f 80 [2] eb 98 [2] ac 9a [2] eb 8b [2] a5 87 [2] a9 8d [2] be 86 [2] a5 c8 [2] 98 }

  condition:
    any of them
}