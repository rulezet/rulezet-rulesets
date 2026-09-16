rule TTP_XOR_MULT_DOSStub_6b24 {
  strings:
    $key_6b24 = { 3f 4c [2] 4b 54 [2] 0c 56 [2] 4b 47 [2] 05 4b [2] 09 41 [2] 1e 4a [2] 05 04 [2] 38 }

  condition:
    any of them
}