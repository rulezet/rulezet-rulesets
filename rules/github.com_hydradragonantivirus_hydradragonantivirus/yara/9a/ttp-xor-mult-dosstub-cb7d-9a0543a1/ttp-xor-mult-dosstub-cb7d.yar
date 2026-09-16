rule TTP_XOR_MULT_DOSStub_cb7d {
  strings:
    $key_cb7d = { 9f 15 [2] eb 0d [2] ac 0f [2] eb 1e [2] a5 12 [2] a9 18 [2] be 13 [2] a5 5d [2] 98 }

  condition:
    any of them
}