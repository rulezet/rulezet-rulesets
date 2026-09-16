rule TTP_XOR_MULT_DOSStub_dd6b {
  strings:
    $key_dd6b = { 89 03 [2] fd 1b [2] ba 19 [2] fd 08 [2] b3 04 [2] bf 0e [2] a8 05 [2] b3 4b [2] 8e }

  condition:
    any of them
}