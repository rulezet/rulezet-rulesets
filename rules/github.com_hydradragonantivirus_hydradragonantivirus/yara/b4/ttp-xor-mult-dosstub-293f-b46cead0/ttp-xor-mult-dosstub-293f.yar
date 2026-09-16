rule TTP_XOR_MULT_DOSStub_293f {
  strings:
    $key_293f = { 7d 57 [2] 09 4f [2] 4e 4d [2] 09 5c [2] 47 50 [2] 4b 5a [2] 5c 51 [2] 47 1f [2] 7a }

  condition:
    any of them
}