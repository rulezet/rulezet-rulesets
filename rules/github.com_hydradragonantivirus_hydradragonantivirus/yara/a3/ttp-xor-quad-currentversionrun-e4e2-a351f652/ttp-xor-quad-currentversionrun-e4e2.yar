rule TTP_XOR_QUAD_CurrentVersionRun_e4e2 {
  strings:
    $key_e4e2 = { b7 8d [2] 93 83 [2] b8 af [2] 96 8d [2] 82 96 [2] 8d 8c [2] 93 91 [2] 91 90 [2] 8a 96 [2] 96 91 [2] 8a be }

  condition:
    any of them
}