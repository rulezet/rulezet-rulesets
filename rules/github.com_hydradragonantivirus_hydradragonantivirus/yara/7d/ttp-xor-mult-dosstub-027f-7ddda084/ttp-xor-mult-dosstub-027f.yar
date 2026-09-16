rule TTP_XOR_MULT_DOSStub_027f {
  strings:
    $key_027f = { 56 17 [2] 22 0f [2] 65 0d [2] 22 1c [2] 6c 10 [2] 60 1a [2] 77 11 [2] 6c 5f [2] 51 }

  condition:
    any of them
}