rule TTP_XOR_QUAD_CurrentVersionRun_e40e {
  strings:
    $key_e40e = { b7 61 [2] 93 6f [2] b8 43 [2] 96 61 [2] 82 7a [2] 8d 60 [2] 93 7d [2] 91 7c [2] 8a 7a [2] 96 7d [2] 8a 52 }

  condition:
    any of them
}