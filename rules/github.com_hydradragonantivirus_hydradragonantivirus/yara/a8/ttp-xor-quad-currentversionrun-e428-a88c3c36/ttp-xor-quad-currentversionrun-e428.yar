rule TTP_XOR_QUAD_CurrentVersionRun_e428 {
  strings:
    $key_e428 = { b7 47 [2] 93 49 [2] b8 65 [2] 96 47 [2] 82 5c [2] 8d 46 [2] 93 5b [2] 91 5a [2] 8a 5c [2] 96 5b [2] 8a 74 }

  condition:
    any of them
}