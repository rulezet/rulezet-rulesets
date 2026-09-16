rule TTP_XOR_MULT_DOSStub_1fff {
  strings:
    $key_1fff = { 4b 97 [2] 3f 8f [2] 78 8d [2] 3f 9c [2] 71 90 [2] 7d 9a [2] 6a 91 [2] 71 df [2] 4c }

  condition:
    any of them
}