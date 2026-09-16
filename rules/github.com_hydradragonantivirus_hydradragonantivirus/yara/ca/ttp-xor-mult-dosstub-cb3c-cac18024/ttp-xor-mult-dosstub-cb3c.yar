rule TTP_XOR_MULT_DOSStub_cb3c {
  strings:
    $key_cb3c = { 9f 54 [2] eb 4c [2] ac 4e [2] eb 5f [2] a5 53 [2] a9 59 [2] be 52 [2] a5 1c [2] 98 }

  condition:
    any of them
}