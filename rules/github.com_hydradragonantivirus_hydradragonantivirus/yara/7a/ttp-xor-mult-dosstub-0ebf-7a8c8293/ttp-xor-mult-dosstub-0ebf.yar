rule TTP_XOR_MULT_DOSStub_0ebf {
  strings:
    $key_0ebf = { 5a d7 [2] 2e cf [2] 69 cd [2] 2e dc [2] 60 d0 [2] 6c da [2] 7b d1 [2] 60 9f [2] 5d }

  condition:
    any of them
}