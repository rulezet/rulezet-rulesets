rule TTP_XOR_QUAD_CurrentVersionRun_4099 {
  strings:
    $key_4099 = { 13 f6 [2] 37 f8 [2] 1c d4 [2] 32 f6 [2] 26 ed [2] 29 f7 [2] 37 ea [2] 35 eb [2] 2e ed [2] 32 ea [2] 2e c5 }

  condition:
    any of them
}