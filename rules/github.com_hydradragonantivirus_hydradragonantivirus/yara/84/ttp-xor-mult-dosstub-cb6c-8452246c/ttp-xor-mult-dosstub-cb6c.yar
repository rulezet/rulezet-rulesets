rule TTP_XOR_MULT_DOSStub_cb6c {
  strings:
    $key_cb6c = { 9f 04 [2] eb 1c [2] ac 1e [2] eb 0f [2] a5 03 [2] a9 09 [2] be 02 [2] a5 4c [2] 98 }

  condition:
    any of them
}