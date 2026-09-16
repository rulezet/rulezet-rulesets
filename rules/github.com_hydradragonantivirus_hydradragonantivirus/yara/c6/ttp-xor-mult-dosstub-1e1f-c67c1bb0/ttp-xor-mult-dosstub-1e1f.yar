rule TTP_XOR_MULT_DOSStub_1e1f {
  strings:
    $key_1e1f = { 4a 77 [2] 3e 6f [2] 79 6d [2] 3e 7c [2] 70 70 [2] 7c 7a [2] 6b 71 [2] 70 3f [2] 4d }

  condition:
    any of them
}