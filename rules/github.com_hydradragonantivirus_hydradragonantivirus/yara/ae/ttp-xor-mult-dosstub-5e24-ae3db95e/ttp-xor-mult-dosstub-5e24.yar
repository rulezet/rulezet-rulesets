rule TTP_XOR_MULT_DOSStub_5e24 {
  strings:
    $key_5e24 = { 0a 4c [2] 7e 54 [2] 39 56 [2] 7e 47 [2] 30 4b [2] 3c 41 [2] 2b 4a [2] 30 04 [2] 0d }

  condition:
    any of them
}