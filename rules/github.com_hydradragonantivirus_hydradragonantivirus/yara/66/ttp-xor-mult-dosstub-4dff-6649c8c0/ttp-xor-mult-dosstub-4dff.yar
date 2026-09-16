rule TTP_XOR_MULT_DOSStub_4dff {
  strings:
    $key_4dff = { 19 97 [2] 6d 8f [2] 2a 8d [2] 6d 9c [2] 23 90 [2] 2f 9a [2] 38 91 [2] 23 df [2] 1e }

  condition:
    any of them
}