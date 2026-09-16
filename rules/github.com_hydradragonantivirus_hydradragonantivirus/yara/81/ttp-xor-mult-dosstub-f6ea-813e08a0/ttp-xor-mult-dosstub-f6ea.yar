rule TTP_XOR_MULT_DOSStub_f6ea {
  strings:
    $key_f6ea = { a2 82 [2] d6 9a [2] 91 98 [2] d6 89 [2] 98 85 [2] 94 8f [2] 83 84 [2] 98 ca [2] a5 }

  condition:
    any of them
}