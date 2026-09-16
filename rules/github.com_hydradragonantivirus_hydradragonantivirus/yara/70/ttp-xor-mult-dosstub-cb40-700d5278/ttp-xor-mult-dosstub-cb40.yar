rule TTP_XOR_MULT_DOSStub_cb40 {
  strings:
    $key_cb40 = { 9f 28 [2] eb 30 [2] ac 32 [2] eb 23 [2] a5 2f [2] a9 25 [2] be 2e [2] a5 60 [2] 98 }

  condition:
    any of them
}