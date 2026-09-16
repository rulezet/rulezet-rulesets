rule TTP_XOR_MULT_DOSStub_fade {
  strings:
    $key_fade = { ae b6 [2] da ae [2] 9d ac [2] da bd [2] 94 b1 [2] 98 bb [2] 8f b0 [2] 94 fe [2] a9 }

  condition:
    any of them
}