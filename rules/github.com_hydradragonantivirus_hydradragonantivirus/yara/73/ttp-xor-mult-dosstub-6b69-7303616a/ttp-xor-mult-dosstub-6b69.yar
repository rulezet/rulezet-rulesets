rule TTP_XOR_MULT_DOSStub_6b69 {
  strings:
    $key_6b69 = { 3f 01 [2] 4b 19 [2] 0c 1b [2] 4b 0a [2] 05 06 [2] 09 0c [2] 1e 07 [2] 05 49 [2] 38 }

  condition:
    any of them
}