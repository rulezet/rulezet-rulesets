rule TTP_XOR_MULT_DOSStub_dd0f {
  strings:
    $key_dd0f = { 89 67 [2] fd 7f [2] ba 7d [2] fd 6c [2] b3 60 [2] bf 6a [2] a8 61 [2] b3 2f [2] 8e }

  condition:
    any of them
}