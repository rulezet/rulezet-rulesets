rule TTP_XOR_QUAD_CurrentVersionRun_e6e2 {
  strings:
    $key_e6e2 = { b5 8d [2] 91 83 [2] ba af [2] 94 8d [2] 80 96 [2] 8f 8c [2] 91 91 [2] 93 90 [2] 88 96 [2] 94 91 [2] 88 be }

  condition:
    any of them
}