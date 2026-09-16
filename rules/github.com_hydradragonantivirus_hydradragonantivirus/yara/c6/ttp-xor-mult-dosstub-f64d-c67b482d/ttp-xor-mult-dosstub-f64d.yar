rule TTP_XOR_MULT_DOSStub_f64d {
  strings:
    $key_f64d = { a2 25 [2] d6 3d [2] 91 3f [2] d6 2e [2] 98 22 [2] 94 28 [2] 83 23 [2] 98 6d [2] a5 }

  condition:
    any of them
}