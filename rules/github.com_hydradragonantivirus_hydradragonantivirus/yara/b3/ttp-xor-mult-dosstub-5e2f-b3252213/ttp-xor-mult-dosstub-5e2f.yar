rule TTP_XOR_MULT_DOSStub_5e2f {
  strings:
    $key_5e2f = { 0a 47 [2] 7e 5f [2] 39 5d [2] 7e 4c [2] 30 40 [2] 3c 4a [2] 2b 41 [2] 30 0f [2] 0d }

  condition:
    any of them
}