rule TTP_XOR_QUAD_CurrentVersionRun_fec2 {
  strings:
    $key_fec2 = { ad ad [2] 89 a3 [2] a2 8f [2] 8c ad [2] 98 b6 [2] 97 ac [2] 89 b1 [2] 8b b0 [2] 90 b6 [2] 8c b1 [2] 90 9e }

  condition:
    any of them
}