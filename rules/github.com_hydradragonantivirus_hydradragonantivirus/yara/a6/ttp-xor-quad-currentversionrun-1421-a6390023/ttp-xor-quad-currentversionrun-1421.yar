rule TTP_XOR_QUAD_CurrentVersionRun_1421 {
  strings:
    $key_1421 = { 47 4e [2] 63 40 [2] 48 6c [2] 66 4e [2] 72 55 [2] 7d 4f [2] 63 52 [2] 61 53 [2] 7a 55 [2] 66 52 [2] 7a 7d }

  condition:
    any of them
}