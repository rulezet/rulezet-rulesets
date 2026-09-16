rule TTP_XOR_MULT_DOSStub_cb4f {
  strings:
    $key_cb4f = { 9f 27 [2] eb 3f [2] ac 3d [2] eb 2c [2] a5 20 [2] a9 2a [2] be 21 [2] a5 6f [2] 98 }

  condition:
    any of them
}