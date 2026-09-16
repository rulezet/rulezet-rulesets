rule TTP_XOR_MULT_DOSStub_7e23 {
  strings:
    $key_7e23 = { 2a 4b [2] 5e 53 [2] 19 51 [2] 5e 40 [2] 10 4c [2] 1c 46 [2] 0b 4d [2] 10 03 [2] 2d }

  condition:
    any of them
}