rule TTP_XOR_MULT_DOSStub_cb66 {
  strings:
    $key_cb66 = { 9f 0e [2] eb 16 [2] ac 14 [2] eb 05 [2] a5 09 [2] a9 03 [2] be 08 [2] a5 46 [2] 98 }

  condition:
    any of them
}