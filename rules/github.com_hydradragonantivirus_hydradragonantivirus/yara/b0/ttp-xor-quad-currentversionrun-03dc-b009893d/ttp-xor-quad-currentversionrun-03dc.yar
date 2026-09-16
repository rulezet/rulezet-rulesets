rule TTP_XOR_QUAD_CurrentVersionRun_03dc {
  strings:
    $key_03dc = { 50 b3 [2] 74 bd [2] 5f 91 [2] 71 b3 [2] 65 a8 [2] 6a b2 [2] 74 af [2] 76 ae [2] 6d a8 [2] 71 af [2] 6d 80 }

  condition:
    any of them
}