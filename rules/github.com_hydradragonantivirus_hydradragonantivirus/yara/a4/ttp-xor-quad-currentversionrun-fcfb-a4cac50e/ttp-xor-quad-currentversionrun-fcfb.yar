rule TTP_XOR_QUAD_CurrentVersionRun_fcfb {
  strings:
    $key_fcfb = { af 94 [2] 8b 9a [2] a0 b6 [2] 8e 94 [2] 9a 8f [2] 95 95 [2] 8b 88 [2] 89 89 [2] 92 8f [2] 8e 88 [2] 92 a7 }

  condition:
    any of them
}