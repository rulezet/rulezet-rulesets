rule TTP_XOR_MULT_DOSStub_cb3f {
  strings:
    $key_cb3f = { 9f 57 [2] eb 4f [2] ac 4d [2] eb 5c [2] a5 50 [2] a9 5a [2] be 51 [2] a5 1f [2] 98 }

  condition:
    any of them
}