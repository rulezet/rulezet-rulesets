rule TTP_XOR_MULT_DOSStub_cbfb {
  strings:
    $key_cbfb = { 9f 93 [2] eb 8b [2] ac 89 [2] eb 98 [2] a5 94 [2] a9 9e [2] be 95 [2] a5 db [2] 98 }

  condition:
    any of them
}