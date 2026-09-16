rule TTP_XOR_MULT_DOSStub_cb9c {
  strings:
    $key_cb9c = { 9f f4 [2] eb ec [2] ac ee [2] eb ff [2] a5 f3 [2] a9 f9 [2] be f2 [2] a5 bc [2] 98 }

  condition:
    any of them
}