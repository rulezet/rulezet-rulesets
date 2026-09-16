rule TTP_XOR_MULT_DOSStub_dfcd {
  strings:
    $key_dfcd = { 8b a5 [2] ff bd [2] b8 bf [2] ff ae [2] b1 a2 [2] bd a8 [2] aa a3 [2] b1 ed [2] 8c }

  condition:
    any of them
}