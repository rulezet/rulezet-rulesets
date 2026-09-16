rule TTP_XOR_MULT_DOSStub_cb7c {
  strings:
    $key_cb7c = { 9f 14 [2] eb 0c [2] ac 0e [2] eb 1f [2] a5 13 [2] a9 19 [2] be 12 [2] a5 5c [2] 98 }

  condition:
    any of them
}