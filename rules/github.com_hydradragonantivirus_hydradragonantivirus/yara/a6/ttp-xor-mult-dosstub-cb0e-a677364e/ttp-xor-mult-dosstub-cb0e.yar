rule TTP_XOR_MULT_DOSStub_cb0e {
  strings:
    $key_cb0e = { 9f 66 [2] eb 7e [2] ac 7c [2] eb 6d [2] a5 61 [2] a9 6b [2] be 60 [2] a5 2e [2] 98 }

  condition:
    any of them
}