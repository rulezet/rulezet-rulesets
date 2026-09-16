rule TTP_XOR_MULT_DOSStub_cbfe {
  strings:
    $key_cbfe = { 9f 96 [2] eb 8e [2] ac 8c [2] eb 9d [2] a5 91 [2] a9 9b [2] be 90 [2] a5 de [2] 98 }

  condition:
    any of them
}