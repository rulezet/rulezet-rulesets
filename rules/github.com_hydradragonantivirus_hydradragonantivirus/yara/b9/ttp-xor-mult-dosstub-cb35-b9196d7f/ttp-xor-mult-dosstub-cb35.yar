rule TTP_XOR_MULT_DOSStub_cb35 {
  strings:
    $key_cb35 = { 9f 5d [2] eb 45 [2] ac 47 [2] eb 56 [2] a5 5a [2] a9 50 [2] be 5b [2] a5 15 [2] 98 }

  condition:
    any of them
}