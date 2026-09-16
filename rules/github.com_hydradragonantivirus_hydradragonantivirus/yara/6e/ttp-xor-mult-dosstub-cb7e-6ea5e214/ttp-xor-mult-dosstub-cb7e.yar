rule TTP_XOR_MULT_DOSStub_cb7e {
  strings:
    $key_cb7e = { 9f 16 [2] eb 0e [2] ac 0c [2] eb 1d [2] a5 11 [2] a9 1b [2] be 10 [2] a5 5e [2] 98 }

  condition:
    any of them
}