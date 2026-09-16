rule TTP_XOR_MULT_DOSStub_cb58 {
  strings:
    $key_cb58 = { 9f 30 [2] eb 28 [2] ac 2a [2] eb 3b [2] a5 37 [2] a9 3d [2] be 36 [2] a5 78 [2] 98 }

  condition:
    any of them
}