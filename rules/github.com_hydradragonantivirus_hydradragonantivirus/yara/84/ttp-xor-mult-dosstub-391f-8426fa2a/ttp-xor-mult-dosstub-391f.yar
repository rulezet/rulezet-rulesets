rule TTP_XOR_MULT_DOSStub_391f {
  strings:
    $key_391f = { 6d 77 [2] 19 6f [2] 5e 6d [2] 19 7c [2] 57 70 [2] 5b 7a [2] 4c 71 [2] 57 3f [2] 6a }

  condition:
    any of them
}