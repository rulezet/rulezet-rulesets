rule TTP_XOR_MULT_DOSStub_ddeb {
  strings:
    $key_ddeb = { 89 83 [2] fd 9b [2] ba 99 [2] fd 88 [2] b3 84 [2] bf 8e [2] a8 85 [2] b3 cb [2] 8e }

  condition:
    any of them
}