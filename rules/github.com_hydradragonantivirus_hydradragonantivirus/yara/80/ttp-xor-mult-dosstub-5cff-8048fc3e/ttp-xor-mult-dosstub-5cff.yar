rule TTP_XOR_MULT_DOSStub_5cff {
  strings:
    $key_5cff = { 08 97 [2] 7c 8f [2] 3b 8d [2] 7c 9c [2] 32 90 [2] 3e 9a [2] 29 91 [2] 32 df [2] 0f }

  condition:
    any of them
}