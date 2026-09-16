rule TTP_XOR_MULT_DOSStub_273f {
  strings:
    $key_273f = { 73 57 [2] 07 4f [2] 40 4d [2] 07 5c [2] 49 50 [2] 45 5a [2] 52 51 [2] 49 1f [2] 74 }

  condition:
    any of them
}