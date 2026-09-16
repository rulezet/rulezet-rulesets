rule TTP_XOR_MULT_DOSStub_cb1d {
  strings:
    $key_cb1d = { 9f 75 [2] eb 6d [2] ac 6f [2] eb 7e [2] a5 72 [2] a9 78 [2] be 73 [2] a5 3d [2] 98 }

  condition:
    any of them
}