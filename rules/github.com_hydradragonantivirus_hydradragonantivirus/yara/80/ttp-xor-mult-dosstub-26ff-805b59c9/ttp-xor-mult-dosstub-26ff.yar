rule TTP_XOR_MULT_DOSStub_26ff {
  strings:
    $key_26ff = { 72 97 [2] 06 8f [2] 41 8d [2] 06 9c [2] 48 90 [2] 44 9a [2] 53 91 [2] 48 df [2] 75 }

  condition:
    any of them
}