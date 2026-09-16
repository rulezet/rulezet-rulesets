rule TTP_XOR_MULT_DOSStub_cb24 {
  strings:
    $key_cb24 = { 9f 4c [2] eb 54 [2] ac 56 [2] eb 47 [2] a5 4b [2] a9 41 [2] be 4a [2] a5 04 [2] 98 }

  condition:
    any of them
}