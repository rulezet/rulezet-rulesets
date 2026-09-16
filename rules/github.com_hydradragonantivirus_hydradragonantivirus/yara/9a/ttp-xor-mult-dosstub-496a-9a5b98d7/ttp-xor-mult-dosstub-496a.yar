rule TTP_XOR_MULT_DOSStub_496a {
  strings:
    $key_496a = { 1d 02 [2] 69 1a [2] 2e 18 [2] 69 09 [2] 27 05 [2] 2b 0f [2] 3c 04 [2] 27 4a [2] 1a }

  condition:
    any of them
}