rule TTP_XOR_QUAD_CurrentVersionRun_e4e7 {
  strings:
    $key_e4e7 = { b7 88 [2] 93 86 [2] b8 aa [2] 96 88 [2] 82 93 [2] 8d 89 [2] 93 94 [2] 91 95 [2] 8a 93 [2] 96 94 [2] 8a bb }

  condition:
    any of them
}