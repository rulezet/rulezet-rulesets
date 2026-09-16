rule TTP_XOR_QUAD_CurrentVersionRun_e414 {
  strings:
    $key_e414 = { b7 7b [2] 93 75 [2] b8 59 [2] 96 7b [2] 82 60 [2] 8d 7a [2] 93 67 [2] 91 66 [2] 8a 60 [2] 96 67 [2] 8a 48 }

  condition:
    any of them
}