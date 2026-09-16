rule TTP_XOR_MULT_DOSStub_cb4b {
  strings:
    $key_cb4b = { 9f 23 [2] eb 3b [2] ac 39 [2] eb 28 [2] a5 24 [2] a9 2e [2] be 25 [2] a5 6b [2] 98 }

  condition:
    any of them
}