rule TTP_XOR_MULT_DOSStub_6aff {
  strings:
    $key_6aff = { 3e 97 [2] 4a 8f [2] 0d 8d [2] 4a 9c [2] 04 90 [2] 08 9a [2] 1f 91 [2] 04 df [2] 39 }

  condition:
    any of them
}