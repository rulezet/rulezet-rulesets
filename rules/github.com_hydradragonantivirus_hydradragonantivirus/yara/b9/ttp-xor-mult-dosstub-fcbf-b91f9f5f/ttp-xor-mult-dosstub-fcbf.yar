rule TTP_XOR_MULT_DOSStub_fcbf {
  strings:
    $key_fcbf = { a8 d7 [2] dc cf [2] 9b cd [2] dc dc [2] 92 d0 [2] 9e da [2] 89 d1 [2] 92 9f [2] af }

  condition:
    any of them
}