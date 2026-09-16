rule TTP_XOR_MULT_DOSStub_3e64 {
  strings:
    $key_3e64 = { 6a 0c [2] 1e 14 [2] 59 16 [2] 1e 07 [2] 50 0b [2] 5c 01 [2] 4b 0a [2] 50 44 [2] 6d }

  condition:
    any of them
}