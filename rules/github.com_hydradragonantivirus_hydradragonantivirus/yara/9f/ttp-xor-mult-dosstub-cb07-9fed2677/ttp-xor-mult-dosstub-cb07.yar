rule TTP_XOR_MULT_DOSStub_cb07 {
  strings:
    $key_cb07 = { 9f 6f [2] eb 77 [2] ac 75 [2] eb 64 [2] a5 68 [2] a9 62 [2] be 69 [2] a5 27 [2] 98 }

  condition:
    any of them
}