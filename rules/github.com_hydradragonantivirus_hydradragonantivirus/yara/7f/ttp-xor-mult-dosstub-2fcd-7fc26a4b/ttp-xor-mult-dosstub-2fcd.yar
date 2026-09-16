rule TTP_XOR_MULT_DOSStub_2fcd {
  strings:
    $key_2fcd = { 7b a5 [2] 0f bd [2] 48 bf [2] 0f ae [2] 41 a2 [2] 4d a8 [2] 5a a3 [2] 41 ed [2] 7c }

  condition:
    any of them
}