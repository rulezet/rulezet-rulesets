rule TTP_XOR_MULT_DOSStub_2b1f {
  strings:
    $key_2b1f = { 7f 77 [2] 0b 6f [2] 4c 6d [2] 0b 7c [2] 45 70 [2] 49 7a [2] 5e 71 [2] 45 3f [2] 78 }

  condition:
    any of them
}