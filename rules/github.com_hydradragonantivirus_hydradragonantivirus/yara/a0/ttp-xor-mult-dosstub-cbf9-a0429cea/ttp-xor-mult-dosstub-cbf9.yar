rule TTP_XOR_MULT_DOSStub_cbf9 {
  strings:
    $key_cbf9 = { 9f 91 [2] eb 89 [2] ac 8b [2] eb 9a [2] a5 96 [2] a9 9c [2] be 97 [2] a5 d9 [2] 98 }

  condition:
    any of them
}