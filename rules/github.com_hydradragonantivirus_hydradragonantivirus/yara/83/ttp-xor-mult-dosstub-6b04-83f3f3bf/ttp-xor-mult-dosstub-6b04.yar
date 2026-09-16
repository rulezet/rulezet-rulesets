rule TTP_XOR_MULT_DOSStub_6b04 {
  strings:
    $key_6b04 = { 3f 6c [2] 4b 74 [2] 0c 76 [2] 4b 67 [2] 05 6b [2] 09 61 [2] 1e 6a [2] 05 24 [2] 38 }

  condition:
    any of them
}