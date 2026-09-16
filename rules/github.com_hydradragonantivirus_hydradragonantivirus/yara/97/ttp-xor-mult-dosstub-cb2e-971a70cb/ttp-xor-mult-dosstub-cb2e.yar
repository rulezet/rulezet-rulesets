rule TTP_XOR_MULT_DOSStub_cb2e {
  strings:
    $key_cb2e = { 9f 46 [2] eb 5e [2] ac 5c [2] eb 4d [2] a5 41 [2] a9 4b [2] be 40 [2] a5 0e [2] 98 }

  condition:
    any of them
}