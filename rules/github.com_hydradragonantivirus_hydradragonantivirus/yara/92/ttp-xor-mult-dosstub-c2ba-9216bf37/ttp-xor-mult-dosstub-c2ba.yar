rule TTP_XOR_MULT_DOSStub_c2ba {
  strings:
    $key_c2ba = { 96 d2 [2] e2 ca [2] a5 c8 [2] e2 d9 [2] ac d5 [2] a0 df [2] b7 d4 [2] ac 9a [2] 91 }

  condition:
    any of them
}