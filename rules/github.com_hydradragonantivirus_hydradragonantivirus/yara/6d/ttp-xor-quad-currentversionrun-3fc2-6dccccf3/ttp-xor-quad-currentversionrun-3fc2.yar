rule TTP_XOR_QUAD_CurrentVersionRun_3fc2 {
  strings:
    $key_3fc2 = { 6c ad [2] 48 a3 [2] 63 8f [2] 4d ad [2] 59 b6 [2] 56 ac [2] 48 b1 [2] 4a b0 [2] 51 b6 [2] 4d b1 [2] 51 9e }

  condition:
    any of them
}