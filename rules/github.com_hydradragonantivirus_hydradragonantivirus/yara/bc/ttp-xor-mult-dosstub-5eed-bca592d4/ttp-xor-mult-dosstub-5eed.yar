rule TTP_XOR_MULT_DOSStub_5eed {
  strings:
    $key_5eed = { 0a 85 [2] 7e 9d [2] 39 9f [2] 7e 8e [2] 30 82 [2] 3c 88 [2] 2b 83 [2] 30 cd [2] 0d }

  condition:
    any of them
}