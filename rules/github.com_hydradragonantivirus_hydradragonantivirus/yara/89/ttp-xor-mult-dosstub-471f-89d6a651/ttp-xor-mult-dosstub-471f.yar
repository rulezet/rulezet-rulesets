rule TTP_XOR_MULT_DOSStub_471f {
  strings:
    $key_471f = { 13 77 [2] 67 6f [2] 20 6d [2] 67 7c [2] 29 70 [2] 25 7a [2] 32 71 [2] 29 3f [2] 14 }

  condition:
    any of them
}