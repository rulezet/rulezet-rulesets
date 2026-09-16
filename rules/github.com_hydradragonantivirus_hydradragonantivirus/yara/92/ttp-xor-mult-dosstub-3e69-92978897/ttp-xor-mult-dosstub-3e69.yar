rule TTP_XOR_MULT_DOSStub_3e69 {
  strings:
    $key_3e69 = { 6a 01 [2] 1e 19 [2] 59 1b [2] 1e 0a [2] 50 06 [2] 5c 0c [2] 4b 07 [2] 50 49 [2] 6d }

  condition:
    any of them
}