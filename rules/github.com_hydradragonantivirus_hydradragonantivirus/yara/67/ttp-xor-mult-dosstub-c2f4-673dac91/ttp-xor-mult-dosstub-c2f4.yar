rule TTP_XOR_MULT_DOSStub_c2f4 {
  strings:
    $key_c2f4 = { 96 9c [2] e2 84 [2] a5 86 [2] e2 97 [2] ac 9b [2] a0 91 [2] b7 9a [2] ac d4 [2] 91 }

  condition:
    any of them
}