rule TTP_XOR_QUAD_CurrentVersionRun_b9d9 {
  strings:
    $key_b9d9 = { ea b6 [2] ce b8 [2] e5 94 [2] cb b6 [2] df ad [2] d0 b7 [2] ce aa [2] cc ab [2] d7 ad [2] cb aa [2] d7 85 }

  condition:
    any of them
}