rule TTP_XOR_MULT_DOSStub_19da {
  strings:
    $key_19da = { 4d b2 [2] 39 aa [2] 7e a8 [2] 39 b9 [2] 77 b5 [2] 7b bf [2] 6c b4 [2] 77 fa [2] 4a }

  condition:
    any of them
}