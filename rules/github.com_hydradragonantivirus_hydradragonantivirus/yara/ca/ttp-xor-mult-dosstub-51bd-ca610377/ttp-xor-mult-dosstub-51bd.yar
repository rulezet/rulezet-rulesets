rule TTP_XOR_MULT_DOSStub_51bd {
  strings:
    $key_51bd = { 05 d5 [2] 71 cd [2] 36 cf [2] 71 de [2] 3f d2 [2] 33 d8 [2] 24 d3 [2] 3f 9d [2] 02 }

  condition:
    any of them
}