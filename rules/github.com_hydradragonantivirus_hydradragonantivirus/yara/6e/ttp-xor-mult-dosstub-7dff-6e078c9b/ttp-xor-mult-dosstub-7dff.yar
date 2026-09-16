rule TTP_XOR_MULT_DOSStub_7dff {
  strings:
    $key_7dff = { 29 97 [2] 5d 8f [2] 1a 8d [2] 5d 9c [2] 13 90 [2] 1f 9a [2] 08 91 [2] 13 df [2] 2e }

  condition:
    any of them
}