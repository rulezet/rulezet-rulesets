rule TTP_XOR_QUAD_CurrentVersionRun_e6d1 {
  strings:
    $key_e6d1 = { b5 be [2] 91 b0 [2] ba 9c [2] 94 be [2] 80 a5 [2] 8f bf [2] 91 a2 [2] 93 a3 [2] 88 a5 [2] 94 a2 [2] 88 8d }

  condition:
    any of them
}