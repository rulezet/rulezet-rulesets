rule TTP_XOR_MULT_DOSStub_cb7a {
  strings:
    $key_cb7a = { 9f 12 [2] eb 0a [2] ac 08 [2] eb 19 [2] a5 15 [2] a9 1f [2] be 14 [2] a5 5a [2] 98 }

  condition:
    any of them
}