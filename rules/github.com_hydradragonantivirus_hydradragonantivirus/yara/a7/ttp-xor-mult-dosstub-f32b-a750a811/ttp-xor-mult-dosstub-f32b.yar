rule TTP_XOR_MULT_DOSStub_f32b {
  strings:
    $key_f32b = { a7 43 [2] d3 5b [2] 94 59 [2] d3 48 [2] 9d 44 [2] 91 4e [2] 86 45 [2] 9d 0b [2] a0 }

  condition:
    any of them
}