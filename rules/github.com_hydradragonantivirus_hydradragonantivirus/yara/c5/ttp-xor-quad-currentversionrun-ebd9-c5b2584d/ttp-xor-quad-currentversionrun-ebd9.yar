rule TTP_XOR_QUAD_CurrentVersionRun_ebd9 {
  strings:
    $key_ebd9 = { b8 b6 [2] 9c b8 [2] b7 94 [2] 99 b6 [2] 8d ad [2] 82 b7 [2] 9c aa [2] 9e ab [2] 85 ad [2] 99 aa [2] 85 85 }

  condition:
    any of them
}