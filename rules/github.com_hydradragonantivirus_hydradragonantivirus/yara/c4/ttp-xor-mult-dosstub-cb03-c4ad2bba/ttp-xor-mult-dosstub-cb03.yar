rule TTP_XOR_MULT_DOSStub_cb03 {
  strings:
    $key_cb03 = { 9f 6b [2] eb 73 [2] ac 71 [2] eb 60 [2] a5 6c [2] a9 66 [2] be 6d [2] a5 23 [2] 98 }

  condition:
    any of them
}