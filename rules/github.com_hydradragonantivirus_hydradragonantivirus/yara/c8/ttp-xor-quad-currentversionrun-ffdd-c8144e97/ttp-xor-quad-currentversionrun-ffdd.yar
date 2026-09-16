rule TTP_XOR_QUAD_CurrentVersionRun_ffdd {
  strings:
    $key_ffdd = { ac b2 [2] 88 bc [2] a3 90 [2] 8d b2 [2] 99 a9 [2] 96 b3 [2] 88 ae [2] 8a af [2] 91 a9 [2] 8d ae [2] 91 81 }

  condition:
    any of them
}