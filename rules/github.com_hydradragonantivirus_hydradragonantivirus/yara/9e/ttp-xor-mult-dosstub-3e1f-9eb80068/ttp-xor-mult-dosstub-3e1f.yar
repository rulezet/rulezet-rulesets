rule TTP_XOR_MULT_DOSStub_3e1f {
  strings:
    $key_3e1f = { 6a 77 [2] 1e 6f [2] 59 6d [2] 1e 7c [2] 50 70 [2] 5c 7a [2] 4b 71 [2] 50 3f [2] 6d }

  condition:
    any of them
}