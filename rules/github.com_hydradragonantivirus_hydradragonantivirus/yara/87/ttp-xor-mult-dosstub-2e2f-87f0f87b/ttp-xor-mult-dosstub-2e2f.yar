rule TTP_XOR_MULT_DOSStub_2e2f {
  strings:
    $key_2e2f = { 7a 47 [2] 0e 5f [2] 49 5d [2] 0e 4c [2] 40 40 [2] 4c 4a [2] 5b 41 [2] 40 0f [2] 7d }

  condition:
    any of them
}