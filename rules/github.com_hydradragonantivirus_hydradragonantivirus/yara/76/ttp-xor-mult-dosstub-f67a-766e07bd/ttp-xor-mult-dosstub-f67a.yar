rule TTP_XOR_MULT_DOSStub_f67a {
  strings:
    $key_f67a = { a2 12 [2] d6 0a [2] 91 08 [2] d6 19 [2] 98 15 [2] 94 1f [2] 83 14 [2] 98 5a [2] a5 }

  condition:
    any of them
}