rule TTP_XOR_MULT_DOSStub_3e3f {
  strings:
    $key_3e3f = { 6a 57 [2] 1e 4f [2] 59 4d [2] 1e 5c [2] 50 50 [2] 5c 5a [2] 4b 51 [2] 50 1f [2] 6d }

  condition:
    any of them
}