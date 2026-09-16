rule TTP_XOR_MULT_DOSStub_5e23 {
  strings:
    $key_5e23 = { 0a 4b [2] 7e 53 [2] 39 51 [2] 7e 40 [2] 30 4c [2] 3c 46 [2] 2b 4d [2] 30 03 [2] 0d }

  condition:
    any of them
}