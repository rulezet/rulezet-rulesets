rule TTP_XOR_MULT_DOSStub_cb7f {
  strings:
    $key_cb7f = { 9f 17 [2] eb 0f [2] ac 0d [2] eb 1c [2] a5 10 [2] a9 1a [2] be 11 [2] a5 5f [2] 98 }

  condition:
    any of them
}