rule TTP_XOR_MULT_DOSStub_cb71 {
  strings:
    $key_cb71 = { 9f 19 [2] eb 01 [2] ac 03 [2] eb 12 [2] a5 1e [2] a9 14 [2] be 1f [2] a5 51 [2] 98 }

  condition:
    any of them
}