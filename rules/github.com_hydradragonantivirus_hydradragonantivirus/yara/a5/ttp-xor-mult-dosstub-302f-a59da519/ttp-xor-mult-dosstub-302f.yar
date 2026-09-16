rule TTP_XOR_MULT_DOSStub_302f {
  strings:
    $key_302f = { 64 47 [2] 10 5f [2] 57 5d [2] 10 4c [2] 5e 40 [2] 52 4a [2] 45 41 [2] 5e 0f [2] 63 }

  condition:
    any of them
}