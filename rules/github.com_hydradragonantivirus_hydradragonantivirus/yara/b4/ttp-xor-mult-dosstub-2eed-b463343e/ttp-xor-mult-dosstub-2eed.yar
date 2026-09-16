rule TTP_XOR_MULT_DOSStub_2eed {
  strings:
    $key_2eed = { 7a 85 [2] 0e 9d [2] 49 9f [2] 0e 8e [2] 40 82 [2] 4c 88 [2] 5b 83 [2] 40 cd [2] 7d }

  condition:
    any of them
}