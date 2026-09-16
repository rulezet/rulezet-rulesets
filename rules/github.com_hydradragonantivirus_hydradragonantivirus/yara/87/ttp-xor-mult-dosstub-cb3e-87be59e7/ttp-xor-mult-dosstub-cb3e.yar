rule TTP_XOR_MULT_DOSStub_cb3e {
  strings:
    $key_cb3e = { 9f 56 [2] eb 4e [2] ac 4c [2] eb 5d [2] a5 51 [2] a9 5b [2] be 50 [2] a5 1e [2] 98 }

  condition:
    any of them
}