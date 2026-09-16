rule TTP_XOR_MULT_DOSStub_0923 {
  strings:
    $key_0923 = { 5d 4b [2] 29 53 [2] 6e 51 [2] 29 40 [2] 67 4c [2] 6b 46 [2] 7c 4d [2] 67 03 [2] 5a }

  condition:
    any of them
}