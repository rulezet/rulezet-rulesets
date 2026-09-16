rule TTP_XOR_MULT_DOSStub_cb0a {
  strings:
    $key_cb0a = { 9f 62 [2] eb 7a [2] ac 78 [2] eb 69 [2] a5 65 [2] a9 6f [2] be 64 [2] a5 2a [2] 98 }

  condition:
    any of them
}