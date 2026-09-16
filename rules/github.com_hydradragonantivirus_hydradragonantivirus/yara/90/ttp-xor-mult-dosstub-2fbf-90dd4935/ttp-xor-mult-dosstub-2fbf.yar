rule TTP_XOR_MULT_DOSStub_2fbf {
  strings:
    $key_2fbf = { 7b d7 [2] 0f cf [2] 48 cd [2] 0f dc [2] 41 d0 [2] 4d da [2] 5a d1 [2] 41 9f [2] 7c }

  condition:
    any of them
}