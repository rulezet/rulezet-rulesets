rule TTP_XOR_MULT_DOSStub_cb38 {
  strings:
    $key_cb38 = { 9f 50 [2] eb 48 [2] ac 4a [2] eb 5b [2] a5 57 [2] a9 5d [2] be 56 [2] a5 18 [2] 98 }

  condition:
    any of them
}