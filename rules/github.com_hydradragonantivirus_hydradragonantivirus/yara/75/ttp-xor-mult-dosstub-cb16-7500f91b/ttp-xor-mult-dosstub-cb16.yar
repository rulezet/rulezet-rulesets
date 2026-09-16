rule TTP_XOR_MULT_DOSStub_cb16 {
  strings:
    $key_cb16 = { 9f 7e [2] eb 66 [2] ac 64 [2] eb 75 [2] a5 79 [2] a9 73 [2] be 78 [2] a5 36 [2] 98 }

  condition:
    any of them
}