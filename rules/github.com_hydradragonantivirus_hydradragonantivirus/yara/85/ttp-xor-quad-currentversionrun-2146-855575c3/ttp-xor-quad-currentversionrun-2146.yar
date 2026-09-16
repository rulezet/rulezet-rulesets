rule TTP_XOR_QUAD_CurrentVersionRun_2146 {
  strings:
    $key_2146 = { 72 29 [2] 56 27 [2] 7d 0b [2] 53 29 [2] 47 32 [2] 48 28 [2] 56 35 [2] 54 34 [2] 4f 32 [2] 53 35 [2] 4f 1a }

  condition:
    any of them
}