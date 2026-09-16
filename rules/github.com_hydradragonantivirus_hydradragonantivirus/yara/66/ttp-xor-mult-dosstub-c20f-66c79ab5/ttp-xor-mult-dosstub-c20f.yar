rule TTP_XOR_MULT_DOSStub_c20f {
  strings:
    $key_c20f = { 96 67 [2] e2 7f [2] a5 7d [2] e2 6c [2] ac 60 [2] a0 6a [2] b7 61 [2] ac 2f [2] 91 }

  condition:
    any of them
}