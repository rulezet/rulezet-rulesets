rule TTP_XOR_MULT_DOSStub_6b74 {
  strings:
    $key_6b74 = { 3f 1c [2] 4b 04 [2] 0c 06 [2] 4b 17 [2] 05 1b [2] 09 11 [2] 1e 1a [2] 05 54 [2] 38 }

  condition:
    any of them
}