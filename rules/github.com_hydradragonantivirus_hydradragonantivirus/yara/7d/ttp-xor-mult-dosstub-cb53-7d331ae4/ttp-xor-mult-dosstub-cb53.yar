rule TTP_XOR_MULT_DOSStub_cb53 {
  strings:
    $key_cb53 = { 9f 3b [2] eb 23 [2] ac 21 [2] eb 30 [2] a5 3c [2] a9 36 [2] be 3d [2] a5 73 [2] 98 }

  condition:
    any of them
}