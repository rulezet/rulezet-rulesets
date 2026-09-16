rule TTP_XOR_QUAD_CurrentVersionRun_e429 {
  strings:
    $key_e429 = { b7 46 [2] 93 48 [2] b8 64 [2] 96 46 [2] 82 5d [2] 8d 47 [2] 93 5a [2] 91 5b [2] 8a 5d [2] 96 5a [2] 8a 75 }

  condition:
    any of them
}