rule TTP_XOR_MULT_DOSStub_cb57 {
  strings:
    $key_cb57 = { 9f 3f [2] eb 27 [2] ac 25 [2] eb 34 [2] a5 38 [2] a9 32 [2] be 39 [2] a5 77 [2] 98 }

  condition:
    any of them
}