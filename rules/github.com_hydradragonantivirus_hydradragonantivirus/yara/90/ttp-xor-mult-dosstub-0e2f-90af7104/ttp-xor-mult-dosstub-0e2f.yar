rule TTP_XOR_MULT_DOSStub_0e2f {
  strings:
    $key_0e2f = { 5a 47 [2] 2e 5f [2] 69 5d [2] 2e 4c [2] 60 40 [2] 6c 4a [2] 7b 41 [2] 60 0f [2] 5d }

  condition:
    any of them
}