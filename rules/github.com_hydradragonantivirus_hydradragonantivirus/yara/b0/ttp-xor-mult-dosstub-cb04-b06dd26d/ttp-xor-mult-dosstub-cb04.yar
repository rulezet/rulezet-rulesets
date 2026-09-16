rule TTP_XOR_MULT_DOSStub_cb04 {
  strings:
    $key_cb04 = { 9f 6c [2] eb 74 [2] ac 76 [2] eb 67 [2] a5 6b [2] a9 61 [2] be 6a [2] a5 24 [2] 98 }

  condition:
    any of them
}