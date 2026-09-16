rule TTP_XOR_MULT_DOSStub_cb31 {
  strings:
    $key_cb31 = { 9f 59 [2] eb 41 [2] ac 43 [2] eb 52 [2] a5 5e [2] a9 54 [2] be 5f [2] a5 11 [2] 98 }

  condition:
    any of them
}