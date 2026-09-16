rule TTP_XOR_MULT_DOSStub_6bff {
  strings:
    $key_6bff = { 3f 97 [2] 4b 8f [2] 0c 8d [2] 4b 9c [2] 05 90 [2] 09 9a [2] 1e 91 [2] 05 df [2] 38 }

  condition:
    any of them
}