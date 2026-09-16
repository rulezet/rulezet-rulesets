rule TTP_XOR_MULT_DOSStub_0fbf {
  strings:
    $key_0fbf = { 5b d7 [2] 2f cf [2] 68 cd [2] 2f dc [2] 61 d0 [2] 6d da [2] 7a d1 [2] 61 9f [2] 5c }

  condition:
    any of them
}