rule TTP_XOR_QUAD_CurrentVersionRun_3fcf {
  strings:
    $key_3fcf = { 6c a0 [2] 48 ae [2] 63 82 [2] 4d a0 [2] 59 bb [2] 56 a1 [2] 48 bc [2] 4a bd [2] 51 bb [2] 4d bc [2] 51 93 }

  condition:
    any of them
}