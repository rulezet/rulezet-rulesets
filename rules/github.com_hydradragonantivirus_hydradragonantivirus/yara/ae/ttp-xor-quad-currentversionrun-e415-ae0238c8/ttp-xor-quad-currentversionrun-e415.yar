rule TTP_XOR_QUAD_CurrentVersionRun_e415 {
  strings:
    $key_e415 = { b7 7a [2] 93 74 [2] b8 58 [2] 96 7a [2] 82 61 [2] 8d 7b [2] 93 66 [2] 91 67 [2] 8a 61 [2] 96 66 [2] 8a 49 }

  condition:
    any of them
}