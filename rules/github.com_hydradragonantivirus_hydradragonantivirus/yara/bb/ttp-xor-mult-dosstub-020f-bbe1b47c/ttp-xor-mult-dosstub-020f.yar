rule TTP_XOR_MULT_DOSStub_020f {
  strings:
    $key_020f = { 56 67 [2] 22 7f [2] 65 7d [2] 22 6c [2] 6c 60 [2] 60 6a [2] 77 61 [2] 6c 2f [2] 51 }

  condition:
    any of them
}