rule TTP_XOR_MULT_DOSStub_cbf2 {
  strings:
    $key_cbf2 = { 9f 9a [2] eb 82 [2] ac 80 [2] eb 91 [2] a5 9d [2] a9 97 [2] be 9c [2] a5 d2 [2] 98 }

  condition:
    any of them
}