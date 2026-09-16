rule TTP_XOR_MULT_DOSStub_695f {
  strings:
    $key_695f = { 3d 37 [2] 49 2f [2] 0e 2d [2] 49 3c [2] 07 30 [2] 0b 3a [2] 1c 31 [2] 07 7f [2] 3a }

  condition:
    any of them
}