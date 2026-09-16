rule TTP_XOR_MULT_DOSStub_cb4d {
  strings:
    $key_cb4d = { 9f 25 [2] eb 3d [2] ac 3f [2] eb 2e [2] a5 22 [2] a9 28 [2] be 23 [2] a5 6d [2] 98 }

  condition:
    any of them
}