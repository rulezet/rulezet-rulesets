rule TTP_XOR_MULT_DOSStub_6d3f {
  strings:
    $key_6d3f = { 39 57 [2] 4d 4f [2] 0a 4d [2] 4d 5c [2] 03 50 [2] 0f 5a [2] 18 51 [2] 03 1f [2] 3e }

  condition:
    any of them
}