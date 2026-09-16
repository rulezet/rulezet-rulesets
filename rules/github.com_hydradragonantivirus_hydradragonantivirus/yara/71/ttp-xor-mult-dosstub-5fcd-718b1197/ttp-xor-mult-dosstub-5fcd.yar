rule TTP_XOR_MULT_DOSStub_5fcd {
  strings:
    $key_5fcd = { 0b a5 [2] 7f bd [2] 38 bf [2] 7f ae [2] 31 a2 [2] 3d a8 [2] 2a a3 [2] 31 ed [2] 0c }

  condition:
    any of them
}