rule TTP_XOR_MULT_DOSStub_cb60 {
  strings:
    $key_cb60 = { 9f 08 [2] eb 10 [2] ac 12 [2] eb 03 [2] a5 0f [2] a9 05 [2] be 0e [2] a5 40 [2] 98 }

  condition:
    any of them
}