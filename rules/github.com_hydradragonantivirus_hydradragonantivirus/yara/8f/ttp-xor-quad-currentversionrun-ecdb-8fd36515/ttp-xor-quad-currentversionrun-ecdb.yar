rule TTP_XOR_QUAD_CurrentVersionRun_ecdb {
  strings:
    $key_ecdb = { bf b4 [2] 9b ba [2] b0 96 [2] 9e b4 [2] 8a af [2] 85 b5 [2] 9b a8 [2] 99 a9 [2] 82 af [2] 9e a8 [2] 82 87 }

  condition:
    any of them
}