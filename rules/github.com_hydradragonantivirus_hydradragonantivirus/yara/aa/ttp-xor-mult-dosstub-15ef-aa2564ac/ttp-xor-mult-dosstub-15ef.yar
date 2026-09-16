rule TTP_XOR_MULT_DOSStub_15ef {
  strings:
    $key_15ef = { 41 87 [2] 35 9f [2] 72 9d [2] 35 8c [2] 7b 80 [2] 77 8a [2] 60 81 [2] 7b cf [2] 46 }

  condition:
    any of them
}