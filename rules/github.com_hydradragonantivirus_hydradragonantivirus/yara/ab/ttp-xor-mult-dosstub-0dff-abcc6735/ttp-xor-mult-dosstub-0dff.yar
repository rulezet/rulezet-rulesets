rule TTP_XOR_MULT_DOSStub_0dff {
  strings:
    $key_0dff = { 59 97 [2] 2d 8f [2] 6a 8d [2] 2d 9c [2] 63 90 [2] 6f 9a [2] 78 91 [2] 63 df [2] 5e }

  condition:
    any of them
}