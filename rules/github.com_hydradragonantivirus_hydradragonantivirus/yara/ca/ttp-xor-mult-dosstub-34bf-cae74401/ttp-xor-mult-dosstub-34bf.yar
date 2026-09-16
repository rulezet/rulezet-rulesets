rule TTP_XOR_MULT_DOSStub_34bf {
  strings:
    $key_34bf = { 60 d7 [2] 14 cf [2] 53 cd [2] 14 dc [2] 5a d0 [2] 56 da [2] 41 d1 [2] 5a 9f [2] 67 }

  condition:
    any of them
}