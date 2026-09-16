rule TTP_XOR_QUAD_CurrentVersionRun_e693 {
  strings:
    $key_e693 = { b5 fc [2] 91 f2 [2] ba de [2] 94 fc [2] 80 e7 [2] 8f fd [2] 91 e0 [2] 93 e1 [2] 88 e7 [2] 94 e0 [2] 88 cf }

  condition:
    any of them
}