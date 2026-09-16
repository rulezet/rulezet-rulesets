rule TTP_XOR_MULT_DOSStub_cb29 {
  strings:
    $key_cb29 = { 9f 41 [2] eb 59 [2] ac 5b [2] eb 4a [2] a5 46 [2] a9 4c [2] be 47 [2] a5 09 [2] 98 }

  condition:
    any of them
}