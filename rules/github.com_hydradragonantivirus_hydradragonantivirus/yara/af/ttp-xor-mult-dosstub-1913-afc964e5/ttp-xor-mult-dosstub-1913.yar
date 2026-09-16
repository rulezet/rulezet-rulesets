rule TTP_XOR_MULT_DOSStub_1913 {
  strings:
    $key_1913 = { 4d 7b [2] 39 63 [2] 7e 61 [2] 39 70 [2] 77 7c [2] 7b 76 [2] 6c 7d [2] 77 33 [2] 4a }

  condition:
    any of them
}