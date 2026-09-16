rule TTP_XOR_MULT_DOSStub_3e24 {
  strings:
    $key_3e24 = { 6a 4c [2] 1e 54 [2] 59 56 [2] 1e 47 [2] 50 4b [2] 5c 41 [2] 4b 4a [2] 50 04 [2] 6d }

  condition:
    any of them
}