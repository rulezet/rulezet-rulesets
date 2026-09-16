rule TTP_XOR_MULT_DOSStub_1e24 {
  strings:
    $key_1e24 = { 4a 4c [2] 3e 54 [2] 79 56 [2] 3e 47 [2] 70 4b [2] 7c 41 [2] 6b 4a [2] 70 04 [2] 4d }

  condition:
    any of them
}