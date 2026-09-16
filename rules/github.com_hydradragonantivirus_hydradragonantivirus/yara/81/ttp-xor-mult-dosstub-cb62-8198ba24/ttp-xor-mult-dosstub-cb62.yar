rule TTP_XOR_MULT_DOSStub_cb62 {
  strings:
    $key_cb62 = { 9f 0a [2] eb 12 [2] ac 10 [2] eb 01 [2] a5 0d [2] a9 07 [2] be 0c [2] a5 42 [2] 98 }

  condition:
    any of them
}