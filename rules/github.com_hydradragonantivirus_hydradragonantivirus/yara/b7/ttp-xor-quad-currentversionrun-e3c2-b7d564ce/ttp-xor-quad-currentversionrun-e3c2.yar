rule TTP_XOR_QUAD_CurrentVersionRun_e3c2 {
  strings:
    $key_e3c2 = { b0 ad [2] 94 a3 [2] bf 8f [2] 91 ad [2] 85 b6 [2] 8a ac [2] 94 b1 [2] 96 b0 [2] 8d b6 [2] 91 b1 [2] 8d 9e }

  condition:
    any of them
}