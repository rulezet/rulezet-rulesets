rule TTP_XOR_MULT_DOSStub_bb8d {
  strings:
    $key_bb8d = { ef e5 [2] 9b fd [2] dc ff [2] 9b ee [2] d5 e2 [2] d9 e8 [2] ce e3 [2] d5 ad [2] e8 }

  condition:
    any of them
}