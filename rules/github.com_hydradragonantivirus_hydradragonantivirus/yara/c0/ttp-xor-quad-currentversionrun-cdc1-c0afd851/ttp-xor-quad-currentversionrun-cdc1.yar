rule TTP_XOR_QUAD_CurrentVersionRun_cdc1 {
  strings:
    $key_cdc1 = { 9e ae [2] ba a0 [2] 91 8c [2] bf ae [2] ab b5 [2] a4 af [2] ba b2 [2] b8 b3 [2] a3 b5 [2] bf b2 [2] a3 9d }

  condition:
    any of them
}