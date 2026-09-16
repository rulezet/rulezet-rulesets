rule TTP_XOR_MULT_DOSStub_f32a {
  strings:
    $key_f32a = { a7 42 [2] d3 5a [2] 94 58 [2] d3 49 [2] 9d 45 [2] 91 4f [2] 86 44 [2] 9d 0a [2] a0 }

  condition:
    any of them
}