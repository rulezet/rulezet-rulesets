rule TTP_XOR_MULT_DOSStub_248c {
  strings:
    $key_248c = { 70 e4 [2] 04 fc [2] 43 fe [2] 04 ef [2] 4a e3 [2] 46 e9 [2] 51 e2 [2] 4a ac [2] 77 }

  condition:
    any of them
}