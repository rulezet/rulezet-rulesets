rule TTP_XOR_MULT_DOSStub_481d {
  strings:
    $key_481d = { 1c 75 [2] 68 6d [2] 2f 6f [2] 68 7e [2] 26 72 [2] 2a 78 [2] 3d 73 [2] 26 3d [2] 1b }

  condition:
    any of them
}