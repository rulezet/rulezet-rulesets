rule TTP_XOR_MULT_DOSStub_cb77 {
  strings:
    $key_cb77 = { 9f 1f [2] eb 07 [2] ac 05 [2] eb 14 [2] a5 18 [2] a9 12 [2] be 19 [2] a5 57 [2] 98 }

  condition:
    any of them
}