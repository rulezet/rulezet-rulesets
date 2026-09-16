rule TTP_XOR_QUAD_CurrentVersionRun_e656 {
  strings:
    $key_e656 = { b5 39 [2] 91 37 [2] ba 1b [2] 94 39 [2] 80 22 [2] 8f 38 [2] 91 25 [2] 93 24 [2] 88 22 [2] 94 25 [2] 88 0a }

  condition:
    any of them
}