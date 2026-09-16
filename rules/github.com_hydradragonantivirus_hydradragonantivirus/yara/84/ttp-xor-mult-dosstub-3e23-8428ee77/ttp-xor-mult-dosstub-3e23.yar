rule TTP_XOR_MULT_DOSStub_3e23 {
  strings:
    $key_3e23 = { 6a 4b [2] 1e 53 [2] 59 51 [2] 1e 40 [2] 50 4c [2] 5c 46 [2] 4b 4d [2] 50 03 [2] 6d }

  condition:
    any of them
}