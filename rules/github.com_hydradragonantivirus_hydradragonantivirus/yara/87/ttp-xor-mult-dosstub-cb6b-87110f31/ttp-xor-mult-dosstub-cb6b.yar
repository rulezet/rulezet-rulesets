rule TTP_XOR_MULT_DOSStub_cb6b {
  strings:
    $key_cb6b = { 9f 03 [2] eb 1b [2] ac 19 [2] eb 08 [2] a5 04 [2] a9 0e [2] be 05 [2] a5 4b [2] 98 }

  condition:
    any of them
}