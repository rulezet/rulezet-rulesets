rule TTP_XOR_QUAD_CurrentVersionRun_00fb {
  strings:
    $key_00fb = { 53 94 [2] 77 9a [2] 5c b6 [2] 72 94 [2] 66 8f [2] 69 95 [2] 77 88 [2] 75 89 [2] 6e 8f [2] 72 88 [2] 6e a7 }

  condition:
    any of them
}