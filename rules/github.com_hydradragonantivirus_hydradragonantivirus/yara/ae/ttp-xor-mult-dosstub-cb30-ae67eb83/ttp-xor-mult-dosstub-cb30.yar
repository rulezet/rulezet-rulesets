rule TTP_XOR_MULT_DOSStub_cb30 {
  strings:
    $key_cb30 = { 9f 58 [2] eb 40 [2] ac 42 [2] eb 53 [2] a5 5f [2] a9 55 [2] be 5e [2] a5 10 [2] 98 }

  condition:
    any of them
}