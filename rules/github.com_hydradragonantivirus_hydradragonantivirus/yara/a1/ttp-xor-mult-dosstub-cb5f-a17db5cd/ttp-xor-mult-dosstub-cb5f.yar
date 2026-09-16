rule TTP_XOR_MULT_DOSStub_cb5f {
  strings:
    $key_cb5f = { 9f 37 [2] eb 2f [2] ac 2d [2] eb 3c [2] a5 30 [2] a9 3a [2] be 31 [2] a5 7f [2] 98 }

  condition:
    any of them
}