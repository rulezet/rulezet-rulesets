rule TTP_XOR_MULT_DOSStub_6dff {
  strings:
    $key_6dff = { 39 97 [2] 4d 8f [2] 0a 8d [2] 4d 9c [2] 03 90 [2] 0f 9a [2] 18 91 [2] 03 df [2] 3e }

  condition:
    any of them
}