rule TTP_XOR_MULT_DOSStub_cb23 {
  strings:
    $key_cb23 = { 9f 4b [2] eb 53 [2] ac 51 [2] eb 40 [2] a5 4c [2] a9 46 [2] be 4d [2] a5 03 [2] 98 }

  condition:
    any of them
}