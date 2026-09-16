rule TTP_XOR_MULT_DOSStub_c52f {
  strings:
    $key_c52f = { 91 47 [2] e5 5f [2] a2 5d [2] e5 4c [2] ab 40 [2] a7 4a [2] b0 41 [2] ab 0f [2] 96 }

  condition:
    any of them
}