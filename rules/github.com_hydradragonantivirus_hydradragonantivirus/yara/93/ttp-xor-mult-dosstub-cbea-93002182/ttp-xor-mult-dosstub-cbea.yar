rule TTP_XOR_MULT_DOSStub_cbea {
  strings:
    $key_cbea = { 9f 82 [2] eb 9a [2] ac 98 [2] eb 89 [2] a5 85 [2] a9 8f [2] be 84 [2] a5 ca [2] 98 }

  condition:
    any of them
}