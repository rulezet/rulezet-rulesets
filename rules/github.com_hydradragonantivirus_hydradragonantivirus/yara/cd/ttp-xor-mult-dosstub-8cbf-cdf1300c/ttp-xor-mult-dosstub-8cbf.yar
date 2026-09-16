rule TTP_XOR_MULT_DOSStub_8cbf {
  strings:
    $key_8cbf = { d8 d7 [2] ac cf [2] eb cd [2] ac dc [2] e2 d0 [2] ee da [2] f9 d1 [2] e2 9f [2] df }

  condition:
    any of them
}