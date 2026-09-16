rule TTP_XOR_MULT_DOSStub_cbf8 {
  strings:
    $key_cbf8 = { 9f 90 [2] eb 88 [2] ac 8a [2] eb 9b [2] a5 97 [2] a9 9d [2] be 96 [2] a5 d8 [2] 98 }

  condition:
    any of them
}