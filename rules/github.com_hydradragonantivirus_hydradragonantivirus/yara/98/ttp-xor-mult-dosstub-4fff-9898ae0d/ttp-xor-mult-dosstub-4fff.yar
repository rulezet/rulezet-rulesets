rule TTP_XOR_MULT_DOSStub_4fff {
  strings:
    $key_4fff = { 1b 97 [2] 6f 8f [2] 28 8d [2] 6f 9c [2] 21 90 [2] 2d 9a [2] 3a 91 [2] 21 df [2] 1c }

  condition:
    any of them
}