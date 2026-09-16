rule TTP_XOR_MULT_DOSStub_cb3b {
  strings:
    $key_cb3b = { 9f 53 [2] eb 4b [2] ac 49 [2] eb 58 [2] a5 54 [2] a9 5e [2] be 55 [2] a5 1b [2] 98 }

  condition:
    any of them
}