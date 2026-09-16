rule TTP_XOR_MULT_DOSStub_f32c {
  strings:
    $key_f32c = { a7 44 [2] d3 5c [2] 94 5e [2] d3 4f [2] 9d 43 [2] 91 49 [2] 86 42 [2] 9d 0c [2] a0 }

  condition:
    any of them
}