rule TTP_XOR_QUAD_CurrentVersionRun_ffb6 {
  strings:
    $key_ffb6 = { ac d9 [2] 88 d7 [2] a3 fb [2] 8d d9 [2] 99 c2 [2] 96 d8 [2] 88 c5 [2] 8a c4 [2] 91 c2 [2] 8d c5 [2] 91 ea }

  condition:
    any of them
}