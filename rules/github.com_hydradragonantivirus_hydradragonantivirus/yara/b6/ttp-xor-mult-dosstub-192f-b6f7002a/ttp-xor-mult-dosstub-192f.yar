rule TTP_XOR_MULT_DOSStub_192f {
  strings:
    $key_192f = { 4d 47 [2] 39 5f [2] 7e 5d [2] 39 4c [2] 77 40 [2] 7b 4a [2] 6c 41 [2] 77 0f [2] 4a }

  condition:
    any of them
}