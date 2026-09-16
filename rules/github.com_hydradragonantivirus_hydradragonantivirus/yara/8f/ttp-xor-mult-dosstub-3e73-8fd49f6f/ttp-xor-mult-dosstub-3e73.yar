rule TTP_XOR_MULT_DOSStub_3e73 {
  strings:
    $key_3e73 = { 6a 1b [2] 1e 03 [2] 59 01 [2] 1e 10 [2] 50 1c [2] 5c 16 [2] 4b 1d [2] 50 53 [2] 6d }

  condition:
    any of them
}