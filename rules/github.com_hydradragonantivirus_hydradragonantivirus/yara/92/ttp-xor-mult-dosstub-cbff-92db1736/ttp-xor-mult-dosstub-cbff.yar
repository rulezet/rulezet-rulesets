rule TTP_XOR_MULT_DOSStub_cbff {
  strings:
    $key_cbff = { 9f 97 [2] eb 8f [2] ac 8d [2] eb 9c [2] a5 90 [2] a9 9a [2] be 91 [2] a5 df [2] 98 }

  condition:
    any of them
}