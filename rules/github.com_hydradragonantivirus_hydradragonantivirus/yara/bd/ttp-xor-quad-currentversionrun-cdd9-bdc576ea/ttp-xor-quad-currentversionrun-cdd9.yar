rule TTP_XOR_QUAD_CurrentVersionRun_cdd9 {
  strings:
    $key_cdd9 = { 9e b6 [2] ba b8 [2] 91 94 [2] bf b6 [2] ab ad [2] a4 b7 [2] ba aa [2] b8 ab [2] a3 ad [2] bf aa [2] a3 85 }

  condition:
    any of them
}