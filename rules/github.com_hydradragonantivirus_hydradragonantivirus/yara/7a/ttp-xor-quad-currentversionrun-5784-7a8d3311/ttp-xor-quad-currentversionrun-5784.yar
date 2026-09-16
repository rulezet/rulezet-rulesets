rule TTP_XOR_QUAD_CurrentVersionRun_5784 {
  strings:
    $key_5784 = { 04 eb [2] 20 e5 [2] 0b c9 [2] 25 eb [2] 31 f0 [2] 3e ea [2] 20 f7 [2] 22 f6 [2] 39 f0 [2] 25 f7 [2] 39 d8 }

  condition:
    any of them
}