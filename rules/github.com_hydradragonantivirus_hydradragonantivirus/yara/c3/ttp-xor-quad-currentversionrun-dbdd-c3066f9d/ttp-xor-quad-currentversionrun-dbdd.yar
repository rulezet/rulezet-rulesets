rule TTP_XOR_QUAD_CurrentVersionRun_dbdd {
  strings:
    $key_dbdd = { 88 b2 [2] ac bc [2] 87 90 [2] a9 b2 [2] bd a9 [2] b2 b3 [2] ac ae [2] ae af [2] b5 a9 [2] a9 ae [2] b5 81 }

  condition:
    any of them
}