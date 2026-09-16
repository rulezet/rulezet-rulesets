rule TTP_XOR_MULT_DOSStub_cbec {
  strings:
    $key_cbec = { 9f 84 [2] eb 9c [2] ac 9e [2] eb 8f [2] a5 83 [2] a9 89 [2] be 82 [2] a5 cc [2] 98 }

  condition:
    any of them
}