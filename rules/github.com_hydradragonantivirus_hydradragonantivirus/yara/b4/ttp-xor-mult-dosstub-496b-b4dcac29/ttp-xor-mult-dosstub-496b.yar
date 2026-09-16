rule TTP_XOR_MULT_DOSStub_496b {
  strings:
    $key_496b = { 1d 03 [2] 69 1b [2] 2e 19 [2] 69 08 [2] 27 04 [2] 2b 0e [2] 3c 05 [2] 27 4b [2] 1a }

  condition:
    any of them
}